//===-- llvm-mctoll.cpp -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This program is a utility that converts a binary to LLVM IR (.ll file)
//
//===----------------------------------------------------------------------===//

#include "llvm-mctoll.h"
#include "EmitRaisedOutputPass.h"
#include "PeepholeOptimizationPass.h"
#include "Raiser/IncludedFileInfo.h"
#include "Raiser/MCInstOrData.h"
#include "Raiser/MachineFunctionRaiser.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/Symbolize/Symbolize.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCDisassembler/MCRelocationInfo.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/COFFImportFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/Wasm.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <set>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::mctoll;
using namespace object;

static cl::OptionCategory LLVMMCToLLCategory("llvm-mctoll options");

static cl::list<std::string> InputFileNames(cl::Positional,
                                            cl::desc("<input object files>"),
                                            cl::OneOrMore);
static cl::opt<std::string> OutputFilename("outfile",
                                           cl::desc("Output filename"),
                                           cl::value_desc("filename"),
                                           cl::cat(LLVMMCToLLCategory),
                                           cl::NotHidden);
cl::alias OutputFilenameshort("o", cl::desc("Alias for --outfile"),
                              cl::aliasopt(OutputFilename),
                              cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::opt<std::string>
    MCPU("mcpu",
         cl::desc("Target a specific cpu type (-mcpu=help for details)"),
         cl::value_desc("cpu-name"), cl::init(""));

cl::list<std::string>
    MAttrs("mattr", cl::CommaSeparated,
           cl::desc("Target specific attributes (-mattr=help for details)"),
           cl::value_desc("a1,+a2,-a3,..."));

// Output file type. Default is binary bitcode.
cl::opt<CodeGenFileType> OutputFormat(
    "output-format", cl::init(CGFT_AssemblyFile),
    cl::desc("Output format (default: binary bitcode):"),
    cl::values(clEnumValN(CGFT_AssemblyFile, "ll",
                          "Emit llvm text bitcode ('.ll') file"),
               clEnumValN(CGFT_ObjectFile, "bc",
                          "Emit llvm binary bitcode ('.bc') file"),
               clEnumValN(CGFT_Null, "null",
                          "Emit nothing, for performance testing")),
    cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::opt<bool> mctoll::Disassemble("raise", cl::desc("Raise machine instruction"),
                                cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::alias Disassembled("d", cl::desc("Alias for -raise"),
                       cl::aliasopt(Disassemble), cl::cat(LLVMMCToLLCategory),
                       cl::NotHidden);

static cl::opt<bool>
    MachOOpt("macho", cl::desc("Use MachO specific object file parser"));
static cl::alias MachOm("m", cl::desc("Alias for --macho"),
                        cl::aliasopt(MachOOpt));

static cl::opt<bool> NoVerify("disable-verify", cl::Hidden,
                              cl::desc("Do not verify input module"));

cl::opt<std::string>
    mctoll::TripleName("triple", cl::desc("Target triple to disassemble for, "
                                        "see -version for available targets"));

cl::opt<std::string>
    mctoll::ArchName("arch-name", cl::desc("Target arch to disassemble for, "
                                         "see -version for available targets"));

cl::opt<std::string> mctoll::FilterFunctionSet(
    "filter-functions-file",
    cl::desc("Specify which functions to raise via a configuration file."),
    cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::alias static FilterFunctionSetF(
    "f", cl::desc("Alias for --filter-functions-file"),
    cl::aliasopt(FilterFunctionSet), cl::cat(LLVMMCToLLCategory),
    cl::NotHidden);

cl::list<std::string>
    mctoll::FilterSections("section",
                         cl::desc("Operate on the specified sections only. "
                                  "With -macho dump segment,section"));

cl::alias static FilterSectionsj("j", cl::desc("Alias for --section"),
                                 cl::aliasopt(FilterSections));

cl::opt<bool>
    mctoll::PrintImmHex("print-imm-hex",
                      cl::desc("Use hex format for immediate values"));

cl::opt<bool> PrintFaultMaps("fault-map-section",
                             cl::desc("Display contents of faultmap section"));

cl::opt<unsigned long long>
    StartAddress("start-address", cl::desc("Disassemble beginning at address"),
                 cl::value_desc("address"), cl::init(0));
cl::opt<unsigned long long> StopAddress("stop-address",
                                        cl::desc("Stop disassembly at address"),
                                        cl::value_desc("address"),
                                        cl::init(UINT64_MAX));
cl::list<std::string> mctoll::IncludeFileNames(
    "include-files", cl::CommaSeparated,
    cl::desc("List of comma-seperated header files with function prototypes "
             "using standard C syntax."),
    cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::alias static IncludeFileNamesShort(
    "I", cl::desc("Alias for --include-files=<single-header-file>"),
    cl::aliasopt(IncludeFileNames), cl::cat(LLVMMCToLLCategory),
    cl::NotHidden);

cl::opt<std::string> mctoll::CompilationDBDir(
    "compilation-db-path",
    cl::desc("Absolute directory path to either compile_commands.json or "
             "compile_flags.txt with any additional details needed to parse "
             "include files. "
             "See https://clang.llvm.org/docs/JSONCompilationDatabase.html for "
             "details."),
    cl::cat(LLVMMCToLLCategory), cl::NotHidden);

namespace {
static ManagedStatic<std::vector<std::string>> RunPassNames;

struct RunPassOption {
  void operator=(const std::string &Val) const {
    if (Val.empty())
      return;
    SmallVector<StringRef, 8> PassNames;
    StringRef(Val).split(PassNames, ',', -1, false);
    for (auto PassName : PassNames)
      RunPassNames->push_back(std::string(PassName));
  }
};
} // namespace

#define DEBUG_TYPE "mctoll"

static RunPassOption RunPassOpt;

static cl::opt<RunPassOption, true, cl::parser<std::string>> RunPass(
    "run-pass",
    cl::desc("Run compiler only for specified passes (comma separated list)"),
    cl::value_desc("pass-name"), cl::ZeroOrMore, cl::location(RunPassOpt));

namespace {
typedef std::function<bool(llvm::object::SectionRef const &)> FilterPredicate;

class SectionFilterIterator {
public:
  SectionFilterIterator(FilterPredicate P,
                        llvm::object::section_iterator const &I,
                        llvm::object::section_iterator const &E)
      : Predicate(std::move(P)), Iterator(I), End(E) {
    ScanPredicate();
  }
  const llvm::object::SectionRef &operator*() const { return *Iterator; }
  SectionFilterIterator &operator++() {
    ++Iterator;
    ScanPredicate();
    return *this;
  }
  bool operator!=(SectionFilterIterator const &Other) const {
    return Iterator != Other.Iterator;
  }

private:
  void ScanPredicate() {
    while (Iterator != End && !Predicate(*Iterator)) {
      ++Iterator;
    }
  }
  FilterPredicate Predicate;
  llvm::object::section_iterator Iterator;
  llvm::object::section_iterator End;
};

class SectionFilter {
public:
  SectionFilter(FilterPredicate P, llvm::object::ObjectFile const &O)
      : Predicate(std::move(P)), Object(O) {}
  SectionFilterIterator begin() {
    return SectionFilterIterator(Predicate, Object.section_begin(),
                                 Object.section_end());
  }
  SectionFilterIterator end() {
    return SectionFilterIterator(Predicate, Object.section_end(),
                                 Object.section_end());
  }

private:
  FilterPredicate Predicate;
  llvm::object::ObjectFile const &Object;
};
SectionFilter ToolSectionFilter(llvm::object::ObjectFile const &O) {
  return SectionFilter(
      [](llvm::object::SectionRef const &S) {
        if (FilterSections.empty())
          return true;
        llvm::StringRef String;
        if (auto NameOrErr = S.getName())
          String = *NameOrErr;
        else {
          consumeError(NameOrErr.takeError());
          return false;
        }

        return is_contained(FilterSections, String);
      },
      O);
}
} // namespace

static const Target *getTarget(const ObjectFile *Obj = nullptr) {
  // Figure out the target triple.
  llvm::Triple TheTriple("unknown-unknown-unknown");
  if (mctoll::TripleName.empty()) {
    if (Obj) {
      auto Arch = Obj->getArch();
      TheTriple.setArch(Triple::ArchType(Arch));

      // For ARM targets, try to use the build attributes to build determine
      // the build target. Target features are also added, but later during
      // disassembly.
      if (Arch == Triple::arm || Arch == Triple::armeb) {
        Obj->setARMSubArch(TheTriple);
      }

      // TheTriple defaults to ELF, and COFF doesn't have an environment:
      // the best we can do here is indicate that it is mach-o.
      if (Obj->isMachO())
        TheTriple.setObjectFormat(Triple::MachO);

      if (Obj->isCOFF()) {
        const auto COFFObj = dyn_cast<COFFObjectFile>(Obj);
        if (COFFObj->getArch() == Triple::thumb)
          TheTriple.setTriple("thumbv7-windows");
      }
    }
  } else {
    TheTriple.setTriple(Triple::normalize(TripleName));
    // Use the triple, but also try to combine with ARM build attributes.
    if (Obj) {
      auto Arch = Obj->getArch();
      if (Arch == Triple::arm || Arch == Triple::armeb) {
        Obj->setARMSubArch(TheTriple);
      }
    }
  }

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget =
      TargetRegistry::lookupTarget(mctoll::ArchName, TheTriple, Error);
  if (!TheTarget) {
    if (Obj)
      report_error(Obj->getFileName(), "Support for raising " +
                                           TheTriple.getArchName() +
                                           " not included");
    else
      error("Unsupported target " + TheTriple.getArchName());
  }

  // A few of opcodes in ARMv4 or ARMv5 are indentified as ARMv6 opcodes,
  // so unify the triple Archs lower then ARMv6 to ARMv6 temporarily.
  if (TheTriple.getArchName() == "armv4t" ||
      TheTriple.getArchName() == "armv5te" ||
      TheTriple.getArchName() == "armv5" || TheTriple.getArchName() == "armv5t")
    TheTriple.setArchName("armv6");

  // Update the triple name and return the found target.
  TripleName = TheTriple.getTriple();
  return TheTarget;
}

static std::unique_ptr<ToolOutputFile> GetOutputStream(StringRef InfileName) {
  // If output file name is not explicitly specified construct a name based on
  // the input file name.
  if (OutputFilename.empty()) {
    // If InputFilename ends in .o, remove it.
    if (InfileName.endswith(".o"))
      OutputFilename = std::string(InfileName.drop_back(2));
    else if (InfileName.endswith(".so"))
      OutputFilename = std::string(InfileName.drop_back(3));
    else
      OutputFilename = std::string(InfileName);

    switch (OutputFormat) {
    case CGFT_AssemblyFile:
      OutputFilename += "-dis.ll";
      break;
    // Just uses enum CGFT_ObjectFile represent llvm bitcode file type
    // provisionally.
    case CGFT_ObjectFile:
      OutputFilename += "-dis.bc";
      break;
    case CGFT_Null:
      OutputFilename += ".null";
      break;
    }
  }

  // Decide if we need "binary" output.
  bool Binary = false;
  switch (OutputFormat) {
  case CGFT_AssemblyFile:
    break;
  case CGFT_ObjectFile:
  case CGFT_Null:
    Binary = true;
    break;
  }

  // Open the file.
  std::error_code EC;
  sys::fs::OpenFlags OpenFlags = sys::fs::OF_None;
  if (!Binary)
    OpenFlags |= sys::fs::OF_Text;
  auto FDOut = std::make_unique<ToolOutputFile>(OutputFilename, EC, OpenFlags);
  if (EC) {
    errs() << EC.message() << '\n';
    return nullptr;
  }

  return FDOut;
}

static bool addPass(PassManagerBase &PM, StringRef toolname, StringRef PassName,
                    TargetPassConfig &TPC) {
  if (PassName == "none")
    return false;

  const PassRegistry *PR = PassRegistry::getPassRegistry();
  const PassInfo *PI = PR->getPassInfo(PassName);
  if (!PI) {
    errs() << toolname << ": run-pass " << PassName << " is not registered.\n";
    return true;
  }

  Pass *P;
  if (PI->getNormalCtor())
    P = PI->getNormalCtor()();
  else {
    errs() << toolname << ": cannot create pass: " << PI->getPassName() << "\n";
    return true;
  }
  std::string Banner = std::string("After ") + std::string(P->getPassName());
  PM.add(P);
  TPC.printAndVerify(Banner);

  return false;
}

bool mctoll::RelocAddressLess(RelocationRef a, RelocationRef b) {
  return a.getOffset() < b.getOffset();
}

namespace {
static bool isArmElf(const ObjectFile *Obj) {
  return (Obj->isELF() &&
          (Obj->getArch() == Triple::aarch64 ||
           Obj->getArch() == Triple::aarch64_be ||
           Obj->getArch() == Triple::arm || Obj->getArch() == Triple::armeb ||
           Obj->getArch() == Triple::thumb ||
           Obj->getArch() == Triple::thumbeb));
}

class PrettyPrinter {
public:
  virtual ~PrettyPrinter() {}
  virtual void printInst(MCInstPrinter &IP, const MCInst *MI,
                         ArrayRef<uint8_t> Bytes, uint64_t Address,
                         raw_ostream &OS, StringRef Annot,
                         MCSubtargetInfo const &STI) {
    OS << format("%8" PRIx64 ":", Address);
    OS << "\t";
    dumpBytes(Bytes, OS);
    if (MI)
      IP.printInst(MI, 0, "", STI, OS);
    else
      OS << " <unknown>";
  }
};
PrettyPrinter PrettyPrinterInst;

PrettyPrinter &selectPrettyPrinter(Triple const &Triple) {
  return PrettyPrinterInst;
}
} // namespace

bool mctoll::isRelocAddressLess(RelocationRef A, RelocationRef B) {
  return A.getOffset() < B.getOffset();
}

template <class ELFT>
static std::error_code getRelocationValueString(const ELFObjectFile<ELFT> *Obj,
                                                const RelocationRef &RelRef,
                                                SmallVectorImpl<char> &Result) {
  DataRefImpl Rel = RelRef.getRawDataRefImpl();

  typedef typename ELFObjectFile<ELFT>::Elf_Sym Elf_Sym;
  typedef typename ELFObjectFile<ELFT>::Elf_Shdr Elf_Shdr;
  typedef typename ELFObjectFile<ELFT>::Elf_Rela Elf_Rela;

  const ELFFile<ELFT> &EF = *Obj->getELFFile();

  auto SecOrErr = EF.getSection(Rel.d.a);
  if (!SecOrErr)
    return errorToErrorCode(SecOrErr.takeError());
  const Elf_Shdr *Sec = *SecOrErr;
  auto SymTabOrErr = EF.getSection(Sec->sh_link);
  if (!SymTabOrErr)
    return errorToErrorCode(SymTabOrErr.takeError());
  const Elf_Shdr *SymTab = *SymTabOrErr;
  assert(SymTab->sh_type == ELF::SHT_SYMTAB ||
         SymTab->sh_type == ELF::SHT_DYNSYM);
  auto StrTabSec = EF.getSection(SymTab->sh_link);
  if (!StrTabSec)
    return errorToErrorCode(StrTabSec.takeError());
  auto StrTabOrErr = EF.getStringTable(*StrTabSec);
  if (!StrTabOrErr)
    return errorToErrorCode(StrTabOrErr.takeError());
  StringRef StrTab = *StrTabOrErr;
  uint8_t type = RelRef.getType();
  StringRef res;
  int64_t addend = 0;
  switch (Sec->sh_type) {
  default:
    return object_error::parse_failed;
  case ELF::SHT_REL: {
    // TODO: Read implicit addend from section data.
    break;
  }
  case ELF::SHT_RELA: {
    const Elf_Rela *ERela = Obj->getRela(Rel);
    addend = ERela->r_addend;
    break;
  }
  }
  symbol_iterator SI = RelRef.getSymbol();
  const Elf_Sym *symb = Obj->getSymbol(SI->getRawDataRefImpl());
  StringRef Target;
  if (symb->getType() == ELF::STT_SECTION) {
    Expected<section_iterator> SymSI = SI->getSection();
    if (!SymSI)
      return errorToErrorCode(SymSI.takeError());
    const Elf_Shdr *SymSec = Obj->getSection((*SymSI)->getRawDataRefImpl());
    auto SecName = EF.getSectionName(SymSec);
    if (!SecName)
      return errorToErrorCode(SecName.takeError());
    Target = *SecName;
  } else {
    Expected<StringRef> SymName = symb->getName(StrTab);
    if (!SymName)
      return errorToErrorCode(SymName.takeError());
    Target = *SymName;
  }
  switch (EF.getHeader()->e_machine) {
  case ELF::EM_X86_64:
    switch (type) {
    case ELF::R_X86_64_PC8:
    case ELF::R_X86_64_PC16:
    case ELF::R_X86_64_PC32: {
      std::string fmtbuf;
      raw_string_ostream fmt(fmtbuf);
      fmt << Target << (addend < 0 ? "" : "+") << addend << "-P";
      fmt.flush();
      Result.append(fmtbuf.begin(), fmtbuf.end());
    } break;
    case ELF::R_X86_64_8:
    case ELF::R_X86_64_16:
    case ELF::R_X86_64_32:
    case ELF::R_X86_64_32S:
    case ELF::R_X86_64_64: {
      std::string fmtbuf;
      raw_string_ostream fmt(fmtbuf);
      fmt << Target << (addend < 0 ? "" : "+") << addend;
      fmt.flush();
      Result.append(fmtbuf.begin(), fmtbuf.end());
    } break;
    default:
      res = "Unknown";
    }
    break;
  case ELF::EM_LANAI:
  case ELF::EM_AVR:
  case ELF::EM_AARCH64: {
    std::string fmtbuf;
    raw_string_ostream fmt(fmtbuf);
    fmt << Target;
    if (addend != 0)
      fmt << (addend < 0 ? "" : "+") << addend;
    fmt.flush();
    Result.append(fmtbuf.begin(), fmtbuf.end());
    break;
  }
  case ELF::EM_386:
  case ELF::EM_IAMCU:
  case ELF::EM_ARM:
  case ELF::EM_HEXAGON:
  case ELF::EM_MIPS:
  case ELF::EM_BPF:
  case ELF::EM_RISCV:
    res = Target;
    break;
  default:
    res = "Unknown";
  }
  if (Result.empty())
    Result.append(res.begin(), res.end());
  return std::error_code();
}

static uint8_t getElfSymbolType(const ObjectFile *Obj, const SymbolRef &Sym) {
  assert(Obj->isELF());
  auto SymbImpl = Sym.getRawDataRefImpl();
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj)) {
    auto SymbOrErr = Elf32LEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      report_error(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj)) {
    auto SymbOrErr = Elf64LEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      report_error(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj)) {
    auto SymbOrErr = Elf32BEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      report_error(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(Obj)) {
    auto SymbOrErr = Elf64BEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      report_error(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  llvm_unreachable("Unsupported binary format");
  // Keep the code analyzer happy
  return ELF::STT_NOTYPE;
}

template <class ELFT>
static void
addDynamicElfSymbols(const ELFObjectFile<ELFT> *Obj,
                     std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  for (auto Symbol : Obj->getDynamicSymbolIterators()) {
    uint8_t SymbolType = Symbol.getELFType();
    if (SymbolType != ELF::STT_FUNC || Symbol.getSize() == 0)
      continue;

    Expected<uint64_t> AddressOrErr = Symbol.getAddress();
    if (!AddressOrErr)
      report_error(AddressOrErr.takeError(), Obj->getFileName());
    uint64_t Address = *AddressOrErr;

    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      report_error(Name.takeError(), Obj->getFileName());
    if (Name->empty())
      continue;

    Expected<section_iterator> SectionOrErr = Symbol.getSection();
    if (!SectionOrErr)
      report_error(SectionOrErr.takeError(), Obj->getFileName());
    section_iterator SecI = *SectionOrErr;
    if (SecI == Obj->section_end())
      continue;

    AllSymbols[*SecI].emplace_back(Address, *Name, SymbolType);
  }
}

static void
addDynamicElfSymbols(const ObjectFile *Obj,
                     std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  assert(Obj->isELF());
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj))
    addDynamicElfSymbols(Elf32LEObj, AllSymbols);
  else if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj))
    addDynamicElfSymbols(Elf64LEObj, AllSymbols);
  else if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj))
    addDynamicElfSymbols(Elf32BEObj, AllSymbols);
  else if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(Obj))
    addDynamicElfSymbols(Elf64BEObj, AllSymbols);
  else
    llvm_unreachable("Unsupported binary format");
}

/*
   A list of symbol entries corresponding to CRT functions added by
   the linker while creating an ELF executable. It is not necessary to
   disassemble and translate these functions.
*/

static std::set<StringRef> ELFCRTSymbols = {
    "call_weak_fn",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "__do_global_dtors_aux_fini_array_entry",
    "_fini",
    "frame_dummy",
    "__frame_dummy_init_array_entry",
    "_init",
    "__init_array_end",
    "__init_array_start",
    "__libc_csu_fini",
    "__libc_csu_init",
    "register_tm_clones",
    "_start",
    "_dl_relocate_static_pie"};

/*
   A list of symbol entries corresponding to CRT functions added by
   the linker while creating an MachO executable. It is not necessary
   to disassemble and translate these functions.
*/

static std::set<StringRef> MachOCRTSymbols = {"__mh_execute_header",
                                              "dyld_stub_binder", "__text",
                                              "__stubs", "__stub_helper"};

/*
   A list of sections whose contents are to be disassembled as code
*/

static std::set<StringRef> ELFSectionsToDisassemble = {".text"};
static std::set<StringRef> MachOSectionsToDisassemble = {};

/* TODO : If it is a C++ binary object symbol, look at the
   signature of the symbol to deduce the return value and return
   type. If the symbol does not include the function signature,
   just create a function that takes no arguments */
/* A non vararg function type with no arguments */
/* TODO: Figure out the symbol linkage type from the symbol
   table. For now assuming global linkage
*/

static bool isAFunctionSymbol(const ObjectFile *Obj, SymbolInfoTy &Symbol) {
  if (Obj->isELF()) {
    return (Symbol.Type == ELF::STT_FUNC);
  }
  if (Obj->isMachO()) {
    // If Symbol is not in the MachOCRTSymbol list return true indicating that
    // this is a symbol of a function we are interested in disassembling and
    // raising.
    return (MachOCRTSymbols.find(Symbol.Name) == MachOCRTSymbols.end());
  }
  return false;
}


//#ifdef __cplusplus
//extern "C" {
//#endif

#define MODULE_RAISER(TargetName) extern "C" void register##TargetName##ModuleRaiser();
#include "Raisers.def"
//#ifdef __cplusplus
//}
//#endif

static void InitializeAllModuleRaisers() {
#define MODULE_RAISER(TargetName) register##TargetName##ModuleRaiser();
#include "Raisers.def"
}

static void DisassembleObject(const ObjectFile *Obj, bool InlineRelocs) {
  if (StartAddress > StopAddress)
    error("Start address should be less than stop address");

  const Target *TheTarget = getTarget(Obj);

  // Package up features to be passed to target/subtarget
  SubtargetFeatures Features = Obj->getFeatures();
  if (MAttrs.size()) {
    for (unsigned i = 0; i != MAttrs.size(); ++i)
      Features.AddFeature(MAttrs[i]);
  }

  std::unique_ptr<const MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI)
    report_error(Obj->getFileName(),
                 "no register info for target " + TripleName);

  MCTargetOptions MCOptions;
  // Set up disassembler.
  std::unique_ptr<const MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  if (!AsmInfo)
    report_error(Obj->getFileName(),
                 "no assembly info for target " + TripleName);
  std::unique_ptr<const MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI)
    report_error(Obj->getFileName(),
                 "no subtarget info for target " + TripleName);
  std::unique_ptr<const MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII)
    report_error(Obj->getFileName(),
                 "no instruction info for target " + TripleName);
  MCObjectFileInfo MOFI;
  MCContext Ctx(Triple(TripleName), AsmInfo.get(), MRI.get(), STI.get());
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.initMCObjectFileInfo(Ctx, /*PIC=*/false);

  std::unique_ptr<MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm)
    report_error(Obj->getFileName(),
                 "no disassembler for target " + TripleName);

  std::unique_ptr<const MCInstrAnalysis> MIA(
      TheTarget->createMCInstrAnalysis(MII.get()));

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP)
    report_error(Obj->getFileName(),
                 "no instruction printer for target " + TripleName);
  IP->setPrintImmHex(PrintImmHex);
  PrettyPrinter &PIP = selectPrettyPrinter(Triple(TripleName));

  LLVMContext llvmCtx;
  std::unique_ptr<TargetMachine> Target(
      TheTarget->createTargetMachine(TripleName, MCPU, Features.getString(),
                                     TargetOptions(), /* RelocModel */ None));
  assert(Target && "Could not allocate target machine!");

  LLVMTargetMachine &llvmTgtMach = static_cast<LLVMTargetMachine &>(*Target);
  MachineModuleInfoWrapperPass *machineModuleInfo =
      new MachineModuleInfoWrapperPass(&llvmTgtMach);
  /* New Module instance with file name */
  Module module(Obj->getFileName(), llvmCtx);
  /* Set datalayout of the module to be the same as LLVMTargetMachine */
  module.setDataLayout(Target->createDataLayout());
  machineModuleInfo->doInitialization(module);
  // Initialize all module raisers that are supported and are part of current
  // LLVM build.
  InitializeAllModuleRaisers();
  // Get the module raiser for Target of the binary being raised
  ModuleRaiser *moduleRaiser = mctoll::getModuleRaiser(Target.get());
  assert((moduleRaiser != nullptr) && "Failed to build module raiser");
  // Set data of module raiser
  moduleRaiser->setModuleRaiserInfo(&module, Target.get(),
                                    &machineModuleInfo->getMMI(), MIA.get(),
                                    MII.get(), Obj, DisAsm.get());

  // Collect dynamic relocations.
  moduleRaiser->collectDynamicRelocations();

  // Create a mapping, RelocSecs = SectionRelocMap[S], where sections
  // in RelocSecs contain the relocations for section S.
  std::error_code EC;
  std::map<SectionRef, SmallVector<SectionRef, 1>> SectionRelocMap;
  for (const SectionRef &Section : ToolSectionFilter(*Obj)) {
    Expected<section_iterator> SecOrErr = Section.getRelocatedSection();
    if (!SecOrErr) {
      break;
    }
    section_iterator Sec2 = *SecOrErr;
    if (Sec2 != Obj->section_end())
      SectionRelocMap[*Sec2].push_back(Section);
  }

  // Create a mapping from virtual address to symbol name.  This is used to
  // pretty print the symbols while disassembling.
  std::map<SectionRef, SectionSymbolsTy> AllSymbols;
  for (const SymbolRef &Symbol : Obj->symbols()) {
    Expected<uint64_t> AddressOrErr = Symbol.getAddress();
    if (!AddressOrErr)
      report_error(AddressOrErr.takeError(), Obj->getFileName());
    uint64_t Address = *AddressOrErr;

    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      report_error(Name.takeError(), Obj->getFileName());
    if (Name->empty())
      continue;

    Expected<section_iterator> SectionOrErr = Symbol.getSection();
    if (!SectionOrErr)
      report_error(SectionOrErr.takeError(), Obj->getFileName());
    section_iterator SecI = *SectionOrErr;
    if (SecI == Obj->section_end())
      continue;

    uint8_t SymbolType = ELF::STT_NOTYPE;
    if (Obj->isELF())
      SymbolType = getElfSymbolType(Obj, Symbol);

    AllSymbols[*SecI].emplace_back(Address, *Name, SymbolType);
  }
  if (AllSymbols.empty() && Obj->isELF())
    addDynamicElfSymbols(Obj, AllSymbols);

  // Create a mapping from virtual address to section.
  std::vector<std::pair<uint64_t, SectionRef>> SectionAddresses;
  for (SectionRef Sec : Obj->sections())
    SectionAddresses.emplace_back(Sec.getAddress(), Sec);
  array_pod_sort(SectionAddresses.begin(), SectionAddresses.end());

  // Linked executables (.exe and .dll files) typically don't include a real
  // symbol table but they might contain an export table.
  if (const auto *COFFObj = dyn_cast<COFFObjectFile>(Obj)) {
    for (const auto &ExportEntry : COFFObj->export_directories()) {
      StringRef Name;
      error(ExportEntry.getSymbolName(Name));
      if (Name.empty())
        continue;

      uint32_t RVA;
      error(ExportEntry.getExportRVA(RVA));

      uint64_t VA = COFFObj->getImageBase() + RVA;
      auto Sec = std::upper_bound(
          SectionAddresses.begin(), SectionAddresses.end(), VA,
          [](uint64_t LHS, const std::pair<uint64_t, SectionRef> &RHS) {
            return LHS < RHS.first;
          });
      if (Sec != SectionAddresses.begin())
        --Sec;
      else
        Sec = SectionAddresses.end();

      if (Sec != SectionAddresses.end())
        AllSymbols[Sec->second].emplace_back(VA, Name, ELF::STT_NOTYPE);
    }
  }

  // Sort all the symbols, this allows us to use a simple binary search to find
  // a symbol near an address.
  for (std::pair<const SectionRef, SectionSymbolsTy> &SecSyms : AllSymbols)
    array_pod_sort(SecSyms.second.begin(), SecSyms.second.end());

  for (const SectionRef &Section : ToolSectionFilter(*Obj)) {
    if ((!Section.isText() || Section.isVirtual()))
      continue;

    StringRef SectionName;
    if (auto NameOrErr = Section.getName())
      SectionName = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());

    uint64_t SectionAddr = Section.getAddress();
    uint64_t SectSize = Section.getSize();
    if (!SectSize)
      continue;

    // Get the list of all the symbols in this section.
    SectionSymbolsTy &Symbols = AllSymbols[Section];
    std::vector<uint64_t> DataMappingSymsAddr;
    std::vector<uint64_t> TextMappingSymsAddr;
    if (isArmElf(Obj)) {
      for (const auto &Symb : Symbols) {
        uint64_t Address = Symb.Addr;
        StringRef Name = Symb.Name;
        if (Name.startswith("$d"))
          DataMappingSymsAddr.push_back(Address - SectionAddr);
        if (Name.startswith("$x"))
          TextMappingSymsAddr.push_back(Address - SectionAddr);
        if (Name.startswith("$a"))
          TextMappingSymsAddr.push_back(Address - SectionAddr);
        if (Name.startswith("$t"))
          TextMappingSymsAddr.push_back(Address - SectionAddr);
      }
    }

    std::sort(DataMappingSymsAddr.begin(), DataMappingSymsAddr.end());
    std::sort(TextMappingSymsAddr.begin(), TextMappingSymsAddr.end());

    if (Obj->isELF() && Obj->getArch() == Triple::amdgcn) {
      // AMDGPU disassembler uses symbolizer for printing labels
      std::unique_ptr<MCRelocationInfo> RelInfo(
          TheTarget->createMCRelocationInfo(TripleName, Ctx));
      if (RelInfo) {
        std::unique_ptr<MCSymbolizer> Symbolizer(TheTarget->createMCSymbolizer(
            TripleName, nullptr, nullptr, &Symbols, &Ctx, std::move(RelInfo)));
        DisAsm->setSymbolizer(std::move(Symbolizer));
      }
    }

    // Make a list of all the relocations for this section.
    std::vector<RelocationRef> Rels;
    if (InlineRelocs) {
      for (const SectionRef &RelocSec : SectionRelocMap[Section]) {
        for (const RelocationRef &Reloc : RelocSec.relocations()) {
          Rels.push_back(Reloc);
        }
      }
    }

    // Sort relocations by address.
    std::sort(Rels.begin(), Rels.end(), RelocAddressLess);

    // If the section has no symbol at the start, just insert a dummy one.
    StringRef name;
    if (Symbols.empty() || Symbols[0].Addr != 0) {
      Symbols.insert(
          Symbols.begin(),
          SymbolInfoTy(SectionAddr, name,
                       Section.isText() ? ELF::STT_FUNC : ELF::STT_OBJECT));
    }

    SmallString<40> Comments;
    raw_svector_ostream CommentStream(Comments);

    StringRef BytesStr =
        unwrapOrError(Section.getContents(), Obj->getFileName());
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(BytesStr.data()),
                            BytesStr.size());

    uint64_t Size;
    uint64_t Index;

    FunctionFilter *FuncFilter = moduleRaiser->getFunctionFilter();
    auto FilterConfigFileName = FilterFunctionSet.getValue();
    if (!FilterConfigFileName.empty()) {
      if (!FuncFilter->readFilterFunctionConfigFile(FilterConfigFileName)) {
        dbgs() << "Unable to read function filter configuration file "
               << FilterConfigFileName << ". Ignoring\n";
      }
    }

    // Build a map of relocations (if they exist in the binary) of text
    // section whose instructions are being raised.
    moduleRaiser->collectTextSectionRelocs(Section);

    // Set used to record all branch targets of a function.
    std::set<uint64_t> branchTargetSet;
    MachineFunctionRaiser *curMFRaiser = nullptr;

    // Disassemble symbol by symbol.
    LLVM_DEBUG(dbgs() << "BEGIN Disassembly of Functions in Section : "
                      << SectionName.data() << "\n");
    for (unsigned si = 0, se = Symbols.size(); si != se; ++si) {
      uint64_t Start = Symbols[si].Addr - SectionAddr;
      // The end is either the section end or the beginning of the next
      // symbol.
      uint64_t End =
          (si == se - 1) ? SectSize : Symbols[si + 1].Addr - SectionAddr;
      // Don't try to disassemble beyond the end of section contents.
      if (End > SectSize)
        End = SectSize;
      // If this symbol has the same address as the next symbol, then skip it.
      if (Start >= End)
        continue;

      // Check if we need to skip symbol
      // Skip if the symbol's data is not between StartAddress and StopAddress
      if (End + SectionAddr < StartAddress ||
          Start + SectionAddr > StopAddress) {
        continue;
      }

      // Stop disassembly at the stop address specified
      if (End + SectionAddr > StopAddress)
        End = StopAddress - SectionAddr;

      if (Obj->isELF() && Obj->getArch() == Triple::amdgcn) {
        // make size 4 bytes folded
        End = Start + ((End - Start) & ~0x3ull);
        if (Symbols[si].Type == ELF::STT_AMDGPU_HSA_KERNEL) {
          // skip amd_kernel_code_t at the begining of kernel symbol (256 bytes)
          Start += 256;
        }
        if (si == se - 1 ||
            Symbols[si + 1].Type == ELF::STT_AMDGPU_HSA_KERNEL) {
          // cut trailing zeroes at the end of kernel
          // cut up to 256 bytes
          const uint64_t EndAlign = 256;
          const auto Limit = End - (std::min)(EndAlign, End - Start);
          while (End > Limit && *reinterpret_cast<const support::ulittle32_t *>(
                                    &Bytes[End - 4]) == 0)
            End -= 4;
        }
      }

      if (isAFunctionSymbol(Obj, Symbols[si])) {
        auto &SymStr = Symbols[si].Name;

        bool raiseFuncSymbol = true;
        if ((!FilterFunctionSet.getValue().empty())) {
          // Check the symbol name whether it should be excluded or not.
          // Check in a non-empty exclude list
          if (!FuncFilter->isFilterSetEmpty(FunctionFilter::FILTER_EXCLUDE)) {
            FunctionFilter::FuncInfo *FI = FuncFilter->findFuncInfoBySymbol(
                SymStr, FunctionFilter::FILTER_EXCLUDE);
            if (FI != nullptr) {
              // Record the function start index.
              FI->StartIdx = Start;
              // Skip raising this function symbol
              raiseFuncSymbol = false;
            }
          }

          if (!FuncFilter->isFilterSetEmpty(FunctionFilter::FILTER_INCLUDE)) {
            // Include list specified. Unless the current function symbol is
            // specified in the include list, skip raising it.
            raiseFuncSymbol = false;
            // Check the symbol name whether it should be included or not.
            if (FuncFilter->findFuncInfoBySymbol(
                    SymStr, FunctionFilter::FILTER_INCLUDE) != nullptr)
              raiseFuncSymbol = true;
          }
        }

        // If Symbol is in the ELFCRTSymbol list return this is a symbol of a
        // function we are not interested in disassembling and raising.
        if (ELFCRTSymbols.find(SymStr) != ELFCRTSymbols.end())
          raiseFuncSymbol = false;

        // Check if raising function symbol should be skipped
        if (!raiseFuncSymbol)
          continue;

        // Note that since LLVM infrastructure was built to be used to build a
        // conventional compiler pipeline, MachineFunction is built well after
        // Function object was created and populated fully. Hence, creation of
        // a Function object is necessary to build MachineFunction.
        // However, in a raiser, we are conceptually walking the traditional
        // compiler pipeline backwards. So we build MachineFunction from
        // the binary before building Function object. Given the dependency,
        // build a place holder Function object to allow for building the
        // MachineFunction object.
        // This Function object is NOT populated when raising MachineFunction
        // abstraction of the binary function. Instead, a new Function is
        // created using the LLVMContext and name of this Function object.
        FunctionType *FTy = FunctionType::get(Type::getVoidTy(llvmCtx), false);
        StringRef FunctionName(Symbols[si].Name);
        // Strip leading underscore if the binary is MachO
        if (Obj->isMachO()) {
          FunctionName.consume_front("_");
        }
        Function *Func = Function::Create(FTy, GlobalValue::ExternalLinkage,
                                          FunctionName, &module);

        // New function symbol encountered. Record all targets collected to
        // current MachineFunctionRaiser before we start parsing the new
        // function bytes.
        curMFRaiser = moduleRaiser->getCurrentMachineFunctionRaiser();
        for (auto target : branchTargetSet) {
          assert(curMFRaiser != nullptr &&
                 "Encountered unintialized MachineFunction raiser object");
          curMFRaiser->getMCInstRaiser()->addTarget(target);
        }

        // Clear the set used to record all branch targets of this function.
        branchTargetSet.clear();
        // Create a new MachineFunction raiser
        curMFRaiser = moduleRaiser->CreateAndAddMachineFunctionRaiser(
            Func, moduleRaiser, Start, End);
        LLVM_DEBUG(dbgs() << "\nFunction " << Symbols[si].Name << ":\n");
      } else {
        // Continue using to the most recent MachineFunctionRaiser
        // Get current MachineFunctionRaiser
        curMFRaiser = moduleRaiser->getCurrentMachineFunctionRaiser();
        // assert(curMFRaiser != nullptr && "Current Machine Function Raiser not
        // initialized");
        if (curMFRaiser == nullptr) {
          // At this point in the instruction stream, we do not have a function
          // symbol to which the bytes being parsed can be made part of. So skip
          // parsing the bytes of this symbol.
          continue;
        }

        // Adjust function end to represent the addition of the content of the
        // current symbol. This represents a situation where we have discovered
        // bytes (most likely data bytes) that belong to the most recent
        // function being parsed.
        MCInstRaiser *mcInstRaiser = curMFRaiser->getMCInstRaiser();
        if (mcInstRaiser->getFuncEnd() < End) {
          assert(mcInstRaiser->adjustFuncEnd(End) &&
                 "Unable to adjust function end value");
        }
      }

      // Get the associated MCInstRaiser
      MCInstRaiser *mcInstRaiser = curMFRaiser->getMCInstRaiser();

      // Start new basic block at the symbol.
      branchTargetSet.insert(Start);

      for (Index = Start; Index < End; Index += Size) {
        MCInst Inst;

        if (Index + SectionAddr < StartAddress ||
            Index + SectionAddr > StopAddress) {
          // skip byte by byte till StartAddress is reached
          Size = 1;
          continue;
        }

        // AArch64 ELF binaries can interleave data and text in the
        // same section. We rely on the markers introduced to
        // understand what we need to dump. If the data marker is within a
        // function, it is denoted as a word/short etc
        if (isArmElf(Obj) && Symbols[si].Type != ELF::STT_OBJECT) {
          uint64_t Stride = 0;

          auto DAI = std::lower_bound(DataMappingSymsAddr.begin(),
                                      DataMappingSymsAddr.end(), Index);
          if (DAI != DataMappingSymsAddr.end() && *DAI == Index) {
            // Switch to data.
            while (Index < End) {
              if (Index + 4 <= End) {
                Stride = 4;
                uint32_t Data = 0;
                if (Obj->isLittleEndian()) {
                  const auto Word =
                      reinterpret_cast<const support::ulittle32_t *>(
                          Bytes.data() + Index);
                  Data = *Word;
                } else {
                  const auto Word = reinterpret_cast<const support::ubig32_t *>(
                      Bytes.data() + Index);
                  Data = *Word;
                }
                mcInstRaiser->addMCInstOrData(Index, Data);
              } else if (Index + 2 <= End) {
                Stride = 2;
                uint16_t Data = 0;
                if (Obj->isLittleEndian()) {
                  const auto Short =
                      reinterpret_cast<const support::ulittle16_t *>(
                          Bytes.data() + Index);
                  Data = *Short;
                } else {
                  const auto Short =
                      reinterpret_cast<const support::ubig16_t *>(Bytes.data() +
                                                                  Index);
                  Data = *Short;
                }
                mcInstRaiser->addMCInstOrData(Index, Data);
              } else {
                Stride = 1;
                mcInstRaiser->addMCInstOrData(Index, Bytes.slice(Index, 1)[0]);
              }
              Index += Stride;

              auto TAI = std::lower_bound(TextMappingSymsAddr.begin(),
                                          TextMappingSymsAddr.end(), Index);
              if (TAI != TextMappingSymsAddr.end() && *TAI == Index)
                break;
            }
          }
        }

        // If there is a data symbol inside an ELF text section and we are
        // only disassembling text, we are in a situation where we must print
        // the data and not disassemble it.
        // TODO : Get rid of the following code in the if-block.
        if (Obj->isELF() && Symbols[si].Type == ELF::STT_OBJECT &&
            Section.isText()) {
          // parse data up to 8 bytes at a time
          uint8_t AsciiData[9] = {'\0'};
          uint8_t Byte;
          int NumBytes = 0;

          for (Index = Start; Index < End; Index += 1) {
            if (((SectionAddr + Index) < StartAddress) ||
                ((SectionAddr + Index) > StopAddress))
              continue;
            if (NumBytes == 0) {
              outs() << format("%8" PRIx64 ":", SectionAddr + Index);
              outs() << "\t";
            }
            Byte = Bytes.slice(Index)[0];
            outs() << format(" %02x", Byte);
            AsciiData[NumBytes] = isprint(Byte) ? Byte : '.';

            uint8_t IndentOffset = 0;
            NumBytes++;
            if (Index == End - 1 || NumBytes > 8) {
              // Indent the space for less than 8 bytes data.
              // 2 spaces for byte and one for space between bytes
              IndentOffset = 3 * (8 - NumBytes);
              for (int Excess = 8 - NumBytes; Excess < 8; Excess++)
                AsciiData[Excess] = '\0';
              NumBytes = 8;
            }
            if (NumBytes == 8) {
              AsciiData[8] = '\0';
              outs() << std::string(IndentOffset, ' ') << "         ";
              outs() << reinterpret_cast<char *>(AsciiData);
              outs() << '\n';
              NumBytes = 0;
            }
          }
        }

        if (Index >= End)
          break;

        // Disassemble a real instruction or a data
        bool Disassembled = DisAsm->getInstruction(
            Inst, Size, Bytes.slice(Index), SectionAddr + Index, CommentStream);
        if (Size == 0)
          Size = 1;

        if (!Disassembled) {
          errs() << "**** Warning: Failed to decode instruction\n";
          PIP.printInst(*IP, Disassembled ? &Inst : nullptr,
                        Bytes.slice(Index, Size), SectionAddr + Index, outs(),
                        "", *STI);
          outs() << CommentStream.str();
          Comments.clear();
          errs() << "\n";
        }

        // Add MCInst to the list if all instructions were decoded
        // successfully till now. Else, do not bother adding since no attempt
        // will be made to raise this function.
        if (Disassembled) {
          mcInstRaiser->addMCInstOrData(Index, Inst);

          // Find branch target and record it. Call targets are not
          // recorded as they are not needed to build per-function CFG.
          if (MIA && MIA->isBranch(Inst)) {
            uint64_t Target;
            if (MIA->evaluateBranch(Inst, Index, Size, Target)) {
              // In a relocatable object, the target's section must reside in
              // the same section as the call instruction or it is accessed
              // through a relocation.
              //
              // In a non-relocatable object, the target may be in any
              // section.
              //
              // N.B. We don't walk the relocations in the relocatable case
              // yet.
              if (!Obj->isRelocatableObject()) {
                auto SectionAddress = std::upper_bound(
                    SectionAddresses.begin(), SectionAddresses.end(), Target,
                    [](uint64_t LHS,
                       const std::pair<uint64_t, SectionRef> &RHS) {
                      return LHS < RHS.first;
                    });
                if (SectionAddress != SectionAddresses.begin()) {
                  --SectionAddress;
                }
              }
              // Add the index Target to target indices set.
              branchTargetSet.insert(Target);
            }

            // Mark the next instruction as a target.
            uint64_t fallThruIndex = Index + Size;
            branchTargetSet.insert(fallThruIndex);
          }
        }
      }
      FuncFilter->eraseFunctionBySymbol(Symbols[si].Name,
                                        FunctionFilter::FILTER_INCLUDE);
    }
    LLVM_DEBUG(dbgs() << "END Disassembly of Functions in Section : "
                      << SectionName.data() << "\n");

    // Record all targets of the last function parsed
    curMFRaiser = moduleRaiser->getCurrentMachineFunctionRaiser();
    for (auto target : branchTargetSet)
      curMFRaiser->getMCInstRaiser()->addTarget(target);

    moduleRaiser->runMachineFunctionPasses();

    if (!FuncFilter->isFilterSetEmpty(FunctionFilter::FILTER_INCLUDE)) {
      errs() << "***** WARNING: The following include filter symbol(s) are not "
                "found :\n";
      FuncFilter->dump(FunctionFilter::FILTER_INCLUDE);
    }
  }

  // Add the pass manager
  Triple TheTriple = Triple(TripleName);

  // Decide where to send the output.
  std::unique_ptr<ToolOutputFile> Out = GetOutputStream(Obj->getFileName());
  if (!Out)
    return;

  // Keep the file created.
  Out->keep();

  auto OS = &Out->os();

  legacy::PassManager PM;

  LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*Target);

  if (RunPassNames->empty()) {
    TargetPassConfig &TPC = *LLVMTM.createPassConfig(PM);
    if (TPC.hasLimitedCodeGenPipeline()) {
      errs() << ToolName << ": run-pass cannot be used with "
             << TPC.getLimitedCodeGenPipelineReason(" and ") << ".\n";
      return;
    }

    TPC.setDisableVerify(NoVerify);
    PM.add(&TPC);
    PM.add(machineModuleInfo);

    // Add optimizations prior to emitting the output file.
    PM.add(new PeepholeOptimizationPass());

    // Add print pass to emit ouptut file.
    PM.add(new EmitRaisedOutputPass(*OS, OutputFormat));

    TPC.printAndVerify("");
    for (const std::string &RunPassName : *RunPassNames) {
      if (addPass(PM, ToolName, RunPassName, TPC))
        return;
    }

    TPC.setInitialized();
  } else if (Target->addPassesToEmitFile(
                 PM, *OS, nullptr, /* no dwarf output file stream*/
                 OutputFormat, NoVerify, machineModuleInfo)) {
    outs() << ToolName << "run system pass!\n";
  }

  cl::PrintOptionValues();
  PM.run(module);
}

static void DumpObject(ObjectFile *o, const Archive *a = nullptr) {
  // Avoid other output when using a raw option.
  LLVM_DEBUG(dbgs() << '\n');
  if (a)
    LLVM_DEBUG(dbgs() << a->getFileName() << "(" << o->getFileName() << ")");
  else
    LLVM_DEBUG(dbgs() << "; " << o->getFileName());
  LLVM_DEBUG(dbgs() << ":\tfile format " << o->getFileFormatName() << "\n\n");

  assert(Disassemble && "Disassemble not set!");
  DisassembleObject(o, /* InlineRelocations */ false);
}

static void DumpObject(const COFFImportFile *I, const Archive *A) {
  assert(false &&
         "This function needs to be deleted and is not expected to be called.");
}

/// @brief Dump each object file in \a a;
static void DumpArchive(const Archive *a) {
  Error Err = Error::success();
  for (auto &C : a->children(Err)) {
    Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
    if (!ChildOrErr) {
      if (auto E = isNotObjectErrorInvalidFileType(ChildOrErr.takeError()))
        report_error(std::move(E), a->getFileName(), C);
      continue;
    }
    if (ObjectFile *o = dyn_cast<ObjectFile>(&*ChildOrErr.get()))
      DumpObject(o, a);
    else if (COFFImportFile *I = dyn_cast<COFFImportFile>(&*ChildOrErr.get()))
      DumpObject(I, a);
    else
      report_error(errorCodeToError(object_error::invalid_file_type),
                   a->getFileName());
  }
  if (Err)
    report_error(std::move(Err), a->getFileName());
}

/// @brief Open file and figure out how to dump it.
static void DumpInput(StringRef file) {
  // If we are using the Mach-O specific object file parser, then let it parse
  // the file and process the command line options.  So the -arch flags can
  // be used to select specific slices, etc.
  if (MachOOpt) {
    parseInputMachO(file);
    return;
  }

  // Attempt to open the binary.
  Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(file);
  if (!BinaryOrErr)
    report_error(BinaryOrErr.takeError(), file);
  Binary &Binary = *BinaryOrErr.get().getBinary();

  if (Archive *a = dyn_cast<Archive>(&Binary))
    DumpArchive(a);
  else if (ObjectFile *o = dyn_cast<ObjectFile>(&Binary)) {
    if (o->getArch() == Triple::x86_64) {
      const ELF64LEObjectFile *Elf64LEObjFile = dyn_cast<ELF64LEObjectFile>(o);
      if (Elf64LEObjFile == nullptr) {
        errs() << "\n\n*** " << file << " : Not 64-bit ELF binary\n"
               << "*** Currently only 64-bit ELF binary raising supported.\n"
               << "*** Please consider contributing support to raise other "
                  "binary formats. Thanks!\n";
        exit(1);
      }
      // Raise x86_64 relocatable binaries (.o files) is not supported.
      auto EType = Elf64LEObjFile->getELFFile().getHeader().e_type;
      if ((EType == ELF::ET_DYN) || (EType == ELF::ET_EXEC))
        DumpObject(o);
      else {
        errs() << "Raising x64 relocatable (.o) x64 binaries not supported\n";
        exit(1);
      }
    } else if (o->getArch() == Triple::arm)
      DumpObject(o);
    else {
      errs() << "\n\n*** No support to raise Binaries other than x64 and ARM\n"
             << "*** Please consider contributing support to raise other "
                "ISAs. Thanks!\n";
      exit(1);
    }
  } else
    report_error(errorCodeToError(object_error::invalid_file_type), file);
}

int main(int argc, char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);
  llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  // Register the target printer for --version.
  cl::AddExtraVersionPrinter(TargetRegistry::printRegisteredTargetsForVersion);

  cl::HideUnrelatedOptions(LLVMMCToLLCategory);

  cl::ParseCommandLineOptions(argc, argv, "MC to LLVM IR raiser\n");

  ToolName = argv[0];

  // Set appropriate bug report message
  llvm::setBugReportMsg(
      "\n*** Please submit an issue at "
      "https://github.com/microsoft/llvm-mctoll"
      "\n*** along with a back trace and a reproducer, if possible.\n");

  // Create a string vector of include files to parse for external definitions
  std::vector<string> IncludeFNames;

  for (auto fname : IncludeFileNames) {
    IncludeFNames.emplace_back(fname);
  }

  // Create a string vector with copy of input file as positional arguments
  // that would be erased as part of include file parsing done by
  // clang::tooling::CommonOptionsParser invoked in
  // getExternalFunctionPrototype().
  std::vector<string> InputFNames;
  for (auto fname : InputFileNames) {
    InputFNames.emplace_back(fname);
  }

  // Stash output file name as well since it would also be reset during parsing
  // done by clang::tooling::CommonOptionsParser invoked in
  // getExternalFunctionPrototype().
  auto OF = OutputFilename.getValue();

  if (!IncludeFNames.empty()) {
    if (!IncludedFileInfo::getExternalFunctionPrototype(IncludeFNames,
                                                        mctoll::CompilationDBDir)) {
      dbgs() << "Unable to read external function prototype. Ignoring\n";
    }
  }
  // Restore stashed Outputfilename
  OutputFilename.setValue(OF);
  // Disassemble contents of .text section.
  Disassemble = true;
  FilterSections.addValue(".text");

  llvm::setCurrentDebugType(DEBUG_TYPE);
  std::for_each(InputFNames.begin(), InputFNames.end(), DumpInput);

  return EXIT_SUCCESS;
}
#undef DEBUG_TYPE
