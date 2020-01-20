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
#include "MCInstOrData.h"
#include "MachineFunctionRaiser.h"
#include "ModuleRaiser.h"
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
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
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
using namespace object;

static cl::OptionCategory LLVMMCToLLCategory("llvm-mctoll options");

static cl::list<std::string> InputFilenames(cl::Positional,
                                            cl::desc("<input object files>"),
                                            cl::ZeroOrMore);
static cl::opt<std::string> OutputFilename("o", cl::desc("Output filename"),
                                           cl::value_desc("filename"),
                                           cl::cat(LLVMMCToLLCategory),
                                           cl::NotHidden);

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

cl::opt<bool> llvm::Disassemble("raise", cl::desc("Raise machine instruction"),
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
    llvm::TripleName("triple", cl::desc("Target triple to disassemble for, "
                                        "see -version for available targets"));

cl::opt<std::string>
    llvm::ArchName("arch-name", cl::desc("Target arch to disassemble for, "
                                         "see -version for available targets"));

cl::opt<std::string> llvm::FilterFunctionSet(
    "filter-functions-file",
    cl::desc("Specify which functions to raise via a configuration file."),
    cl::cat(LLVMMCToLLCategory), cl::NotHidden);

cl::alias static FilterFunctionSetF(
    "f", cl::desc("Alias for --filter-functions-file"),
    cl::aliasopt(llvm::FilterFunctionSet), cl::cat(LLVMMCToLLCategory),
    cl::NotHidden);

cl::opt<bool> llvm::SectionHeaders("section-headers",
                                   cl::desc("Display summaries of the "
                                            "headers for each section."));
static cl::alias SectionHeadersShort("headers",
                                     cl::desc("Alias for --section-headers"),
                                     cl::aliasopt(SectionHeaders));
static cl::alias SectionHeadersShorter("h",
                                       cl::desc("Alias for --section-headers"),
                                       cl::aliasopt(SectionHeaders));

cl::list<std::string>
    llvm::FilterSections("section",
                         cl::desc("Operate on the specified sections only. "
                                  "With -macho dump segment,section"));

cl::alias static FilterSectionsj("j", cl::desc("Alias for --section"),
                                 cl::aliasopt(llvm::FilterSections));

cl::opt<bool> llvm::NoShowRawInsn("no-show-raw-insn",
                                  cl::desc("When disassembling "
                                           "instructions, do not print "
                                           "the instruction bytes."));
cl::opt<bool> llvm::NoLeadingAddr("no-leading-addr",
                                  cl::desc("Print no leading address"));

cl::opt<bool> llvm::UnwindInfo("unwind-info",
                               cl::desc("Display unwind information"));

static cl::alias UnwindInfoShort("u", cl::desc("Alias for --unwind-info"),
                                 cl::aliasopt(UnwindInfo));

cl::opt<bool>
    llvm::PrivateHeaders("private-headers",
                         cl::desc("Display format specific file headers"));

cl::opt<bool> llvm::FirstPrivateHeader(
    "private-header", cl::desc("Display only the first format specific file "
                               "header"));

static cl::alias PrivateHeadersShort("p",
                                     cl::desc("Alias for --private-headers"),
                                     cl::aliasopt(PrivateHeaders));

cl::opt<bool>
    llvm::PrintImmHex("print-imm-hex",
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

namespace {
static ManagedStatic<std::vector<std::string>> RunPassNames;

struct RunPassOption {
  void operator=(const std::string &Val) const {
    if (Val.empty())
      return;
    SmallVector<StringRef, 8> PassNames;
    StringRef(Val).split(PassNames, ',', -1, false);
    for (auto PassName : PassNames)
      RunPassNames->push_back(PassName);
  }
};
} // namespace

static RunPassOption RunPassOpt;

static cl::opt<RunPassOption, true, cl::parser<std::string>> RunPass(
    "run-pass",
    cl::desc("Run compiler only for specified passes (comma separated list)"),
    cl::value_desc("pass-name"), cl::ZeroOrMore, cl::location(RunPassOpt));

static StringRef ToolName;

typedef std::tuple<uint64_t, StringRef, uint8_t> SectionSymbolInfo;
typedef std::vector<SectionSymbolInfo> SectionSymbolsTy;

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

void llvm::error(std::error_code EC) {
  if (!EC)
    return;

  errs() << ToolName << ": error reading file: " << EC.message() << ".\n";
  errs().flush();
  exit(1);
}

void llvm::error(Error E) {
  if (!E)
    return;
  WithColor::error(errs(), ToolName) << toString(std::move(E));
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void llvm::error(Twine Message) {
  errs() << ToolName << ": " << Message << ".\n";
  errs().flush();
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void llvm::report_error(StringRef File, Twine Message) {
  WithColor::error(errs(), ToolName)
      << "'" << File << "': " << Message << ".\n";
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void llvm::report_error(Error E, StringRef File) {
  assert(E);
  std::string Buf;
  raw_string_ostream OS(Buf);
  logAllUnhandledErrors(std::move(E), OS);
  OS.flush();
  WithColor::error(errs(), ToolName) << "'" << File << "': " << Buf;
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void llvm::report_error(Error E, StringRef ArchiveName,
                                                StringRef FileName,
                                                StringRef ArchitectureName) {
  assert(E);
  WithColor::error(errs(), ToolName);
  if (ArchiveName != "")
    errs() << ArchiveName << "(" << FileName << ")";
  else
    errs() << "'" << FileName << "'";
  if (!ArchitectureName.empty())
    errs() << " (for architecture " << ArchitectureName << ")";
  std::string Buf;
  raw_string_ostream OS(Buf);
  logAllUnhandledErrors(std::move(E), OS);
  OS.flush();
  errs() << ": " << Buf;
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void llvm::report_error(Error E, StringRef ArchiveName,
                                                const object::Archive::Child &C,
                                                StringRef ArchitectureName) {
  Expected<StringRef> NameOrErr = C.getName();
  // TODO: if we have a error getting the name then it would be nice to print
  // the index of which archive member this is and or its offset in the
  // archive instead of "???" as the name.
  if (!NameOrErr) {
    consumeError(NameOrErr.takeError());
    report_error(std::move(E), ArchiveName, "???", ArchitectureName);
  } else
    report_error(std::move(E), ArchiveName, NameOrErr.get(), ArchitectureName);
}

static const Target *getTarget(const ObjectFile *Obj = nullptr) {
  // Figure out the target triple.
  llvm::Triple TheTriple("unknown-unknown-unknown");
  if (TripleName.empty()) {
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
      TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    if (Obj)
      report_error(Obj->getFileName(), "Support for raising " +
                                           TheTriple.getArchName() +
                                           " not included");
    else
      error("Unsupported target " + TheTriple.getArchName());
  }

  // Update the triple name and return the found target.
  if (TheTriple.getArchName() == "armv4t" ||
      TheTriple.getArchName() == "armv5te" ||
      TheTriple.getArchName() == "armv5" || TheTriple.getArchName() == "armv5t")
    TheTriple.setArchName("armv6");
  TripleName = TheTriple.getTriple();
  return TheTarget;
}

static std::unique_ptr<ToolOutputFile> GetOutputStream(const char *TargetName,
                                                       Triple::OSType OS,
                                                       const char *ProgName) {
  // If we don't yet have an output filename, make one.
  if (OutputFilename.empty()) {
    // If InputFilename ends in .o, remove it.
    StringRef IFN = InputFilenames[0];
    if (IFN.endswith(".o"))
      OutputFilename = IFN.drop_back(2);
    else if (IFN.endswith(".so"))
      OutputFilename = IFN.drop_back(3);
    else
      OutputFilename = IFN;

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
  sys::fs::OpenFlags OpenFlags = sys::fs::F_None;
  if (!Binary)
    OpenFlags |= sys::fs::F_Text;
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

bool llvm::RelocAddressLess(RelocationRef a, RelocationRef b) {
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
    if (!NoLeadingAddr)
      OS << format("%8" PRIx64 ":", Address);
    if (!NoShowRawInsn) {
      OS << "\t";
      dumpBytes(Bytes, OS);
    }
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

bool llvm::isRelocAddressLess(RelocationRef A, RelocationRef B) {
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
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj))
    return Elf32LEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj))
    return Elf64LEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj))
    return Elf32BEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(Obj))
    return Elf64BEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
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

static bool isAFunctionSymbol(const ObjectFile *Obj,
                              SectionSymbolInfo &Symbol) {
  if (Obj->isELF()) {
    return (std::get<2>(Symbol) == ELF::STT_FUNC);
  }
  if (Obj->isMachO()) {
    // If Symbol is not in the MachOCRTSymbol list return true indicating that
    // this is a symbol of a function we are interested in disassembling and
    // raising.
    return (MachOCRTSymbols.find(std::get<1>(Symbol)) == MachOCRTSymbols.end());
  }
  return false;
}

namespace RaiserContext {
SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;

bool isSupportedArch(Triple::ArchType arch) {
  for (auto m : ModuleRaiserRegistry)
    if (m->getArchType() == arch)
      return true;

  return false;
}

ModuleRaiser *getModuleRaiser(const TargetMachine *tm) {
  ModuleRaiser *mr = nullptr;
  auto arch = tm->getTargetTriple().getArch();
  for (auto m : ModuleRaiserRegistry)
    if (m->getArchType() == arch) {
      mr = m;
      break;
    }
  assert(nullptr != mr && "This arch has not yet supported for raising!\n");
  return mr;
}

} // namespace RaiserContext

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
  MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(Triple(TripleName), false, Ctx);

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
  ModuleRaiser::InitializeAllModuleRaisers();
  // Get the module raiser for Target of the binary being raised
  ModuleRaiser *moduleRaiser = RaiserContext::getModuleRaiser(Target.get());
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
        uint64_t Address = std::get<0>(Symb);
        StringRef Name = std::get<1>(Symb);
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

    StringRef SegmentName = "";
    if (const MachOObjectFile *MachO = dyn_cast<const MachOObjectFile>(Obj)) {
      DataRefImpl DR = Section.getRawDataRefImpl();
      SegmentName = MachO->getSectionFinalSegmentName(DR);
    }

    StringRef name;

    bool PrintAll =
        (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() >
         0);

    if (PrintAll) {
      if ((SectionAddr <= StopAddress) &&
          (SectionAddr + SectSize) >= StartAddress) {
        outs() << "Disassembling section ";
        if (!SegmentName.empty())
          outs() << SegmentName << ",";
        outs() << name << "\n";
      }
    }

    // If the section has no symbol at the start, just insert a dummy one.
    if (Symbols.empty() || std::get<0>(Symbols[0]) != 0) {
      Symbols.insert(
          Symbols.begin(),
          std::make_tuple(SectionAddr, name,
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
    if (cl::getRegisteredOptions()["filter-functions-file"]
            ->getNumOccurrences() > 0) {
      if (!FuncFilter->readFilterFunctionConfigFile(
              FilterFunctionSet.getValue())) {
        dbgs() << "Unable to read function filter configuration file "
               << FilterFunctionSet.getValue() << ". Ignoring\n";
      }
    }

    // Build a map of relocations (if they exist in the binary) of text
    // section whose instructions are being raised.
    moduleRaiser->collectTextSectionRelocs(Section);

    // Set used to record all branch targets of a function.
    std::set<uint64_t> branchTargetSet;
    MachineFunctionRaiser *curMFRaiser = nullptr;

    // Disassemble symbol by symbol.
    for (unsigned si = 0, se = Symbols.size(); si != se; ++si) {
      uint64_t Start = std::get<0>(Symbols[si]) - SectionAddr;
      // The end is either the section end or the beginning of the next
      // symbol.
      uint64_t End = (si == se - 1)
                         ? SectSize
                         : std::get<0>(Symbols[si + 1]) - SectionAddr;
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
        if (std::get<2>(Symbols[si]) == ELF::STT_AMDGPU_HSA_KERNEL) {
          // skip amd_kernel_code_t at the begining of kernel symbol (256 bytes)
          Start += 256;
        }
        if (si == se - 1 ||
            std::get<2>(Symbols[si + 1]) == ELF::STT_AMDGPU_HSA_KERNEL) {
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
        auto &SymStr = std::get<1>(Symbols[si]);

        if ((FilterFunctionSet.getNumOccurrences() != 0)) {
          // Check the symbol name whether it should be excluded or not.
          if (!FuncFilter->isFilterSetEmpty(FunctionFilter::FILTER_EXCLUDE)) {
            FunctionFilter::FuncInfo *FI = FuncFilter->findFuncInfoBySymbol(
                SymStr, FunctionFilter::FILTER_EXCLUDE);
            if (FI != nullptr) {
              // Record the function start index.
              FI->StartIdx = Start;
              continue;
            }
          }

          // Check the symbol name whether it should be included or not.
          if (FuncFilter->findFuncInfoBySymbol(
                  SymStr, FunctionFilter::FILTER_INCLUDE) == nullptr)
            continue;
        }

        // If Symbol is in the ELFCRTSymbol list return this is a symbol of a
        // function we are not interested in disassembling and raising.
        if (ELFCRTSymbols.find(SymStr) != ELFCRTSymbols.end())
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
        StringRef FunctionName(std::get<1>(Symbols[si]));
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
        // Flag to indicate all instructions of the current function were
        // successfully decoded.
        // TODO: As of now, we will only raise functions with all instructions
        // decoded.
        // bool allInstructionsDecoded = true;
        if (PrintAll)
          outs() << "\nFunction " << std::get<1>(Symbols[si]) << ":\n";
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
        if (isArmElf(Obj) && std::get<2>(Symbols[si]) != ELF::STT_OBJECT) {
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
        if (Obj->isELF() && std::get<2>(Symbols[si]) == ELF::STT_OBJECT &&
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

        // allInstructionsDecoded &= Disassembled;
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
      FuncFilter->eraseFunctionBySymbol(std::get<1>(Symbols[si]),
                                        FunctionFilter::FILTER_INCLUDE);
    }

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
  std::unique_ptr<ToolOutputFile> Out =
      GetOutputStream(TheTarget->getName(), TheTriple.getOS(), ToolName.data());

  if (!Out)
    return;

  // Keep the file created.
  Out->keep();

  raw_pwrite_stream *OS = &Out->os();

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

void llvm::PrintSectionHeaders(const ObjectFile *Obj) {
  outs() << "Sections:\n"
            "Idx Name          Size      Address          Type\n";
  unsigned i = 0;
  for (const SectionRef &Section : ToolSectionFilter(*Obj)) {
    StringRef Name = unwrapOrError(Section.getName(), Obj->getFileName());

    uint64_t Address = Section.getAddress();
    uint64_t Size = Section.getSize();
    bool Text = Section.isText();
    bool Data = Section.isData();
    bool BSS = Section.isBSS();
    std::string Type = (std::string(Text ? "TEXT " : "") +
                        (Data ? "DATA " : "") + (BSS ? "BSS" : ""));
    outs() << format("%3d %-13s %08" PRIx64 " %016" PRIx64 " %s\n", i,
                     Name.str().c_str(), Size, Address, Type.c_str());
    ++i;
  }
}

void llvm::PrintSymbolTable(const ObjectFile *o, StringRef ArchiveName,
                            StringRef ArchitectureName) {
  outs() << "SYMBOL TABLE:\n";

  if (const COFFObjectFile *coff = dyn_cast<const COFFObjectFile>(o)) {
    printCOFFSymbolTable(coff);
    return;
  }

  for (const SymbolRef &Symbol : o->symbols()) {
    Expected<uint64_t> AddressOrError = Symbol.getAddress();
    if (!AddressOrError)
      report_error(AddressOrError.takeError(), o->getFileName(), ArchiveName,
                   ArchitectureName);
    uint64_t Address = *AddressOrError;
    if ((Address < StartAddress) || (Address > StopAddress))
      continue;

    Expected<SymbolRef::Type> TypeOrError = Symbol.getType();
    if (!TypeOrError)
      report_error(TypeOrError.takeError(), o->getFileName(), ArchiveName,
                   ArchitectureName);

    SymbolRef::Type Type = *TypeOrError;
    uint32_t Flags = Symbol.getFlags();
    Expected<section_iterator> SectionOrErr = Symbol.getSection();
    if (!SectionOrErr)
      report_error(SectionOrErr.takeError(), o->getFileName(), ArchiveName,
                   ArchitectureName);

    section_iterator Section = *SectionOrErr;
    StringRef Name;
    if (Type == SymbolRef::ST_Debug && Section != o->section_end()) {
      if (auto NameOrErr = Section->getName())
        Name = *NameOrErr;
      else
        consumeError(NameOrErr.takeError());

    } else {
      Expected<StringRef> NameOrErr = Symbol.getName();
      if (!NameOrErr)
        report_error(NameOrErr.takeError(), o->getFileName(), ArchiveName,
                     ArchitectureName);
      Name = *NameOrErr;
    }

    bool Global = Flags & SymbolRef::SF_Global;
    bool Weak = Flags & SymbolRef::SF_Weak;
    bool Absolute = Flags & SymbolRef::SF_Absolute;
    bool Common = Flags & SymbolRef::SF_Common;
    bool Hidden = Flags & SymbolRef::SF_Hidden;

    char GlobLoc = ' ';
    if (Type != SymbolRef::ST_Unknown)
      GlobLoc = Global ? 'g' : 'l';
    char Debug =
        (Type == SymbolRef::ST_Debug || Type == SymbolRef::ST_File) ? 'd' : ' ';
    char FileFunc = ' ';
    if (Type == SymbolRef::ST_File)
      FileFunc = 'f';
    else if (Type == SymbolRef::ST_Function)
      FileFunc = 'F';

    const char *Fmt = o->getBytesInAddress() > 4 ? "%016" PRIx64 : "%08" PRIx64;

    outs() << format(Fmt, Address) << " "
           << GlobLoc            // Local -> 'l', Global -> 'g', Neither -> ' '
           << (Weak ? 'w' : ' ') // Weak?
           << ' '                // Constructor. Not supported yet.
           << ' '                // Warning. Not supported yet.
           << ' '                // Indirect reference to another symbol.
           << Debug              // Debugging (d) or dynamic (D) symbol.
           << FileFunc // Name of function (F), file (f) or object (O).
           << ' ';
    if (Absolute) {
      outs() << "*ABS*";
    } else if (Common) {
      outs() << "*COM*";
    } else if (Section == o->section_end()) {
      outs() << "*UND*";
    } else {
      if (const MachOObjectFile *MachO = dyn_cast<const MachOObjectFile>(o)) {
        DataRefImpl DR = Section->getRawDataRefImpl();
        StringRef SegmentName = MachO->getSectionFinalSegmentName(DR);
        outs() << SegmentName << ",";
      }
      StringRef SectionName =
          unwrapOrError(Section->getName(), o->getFileName());

      outs() << SectionName;
    }

    outs() << '\t';
    if (Common || isa<ELFObjectFileBase>(o)) {
      uint64_t Val =
          Common ? Symbol.getAlignment() : ELFSymbolRef(Symbol).getSize();
      outs() << format("\t %08" PRIx64 " ", Val);
    }

    if (Hidden) {
      outs() << ".hidden ";
    }
    outs() << Name << '\n';
  }
}

void llvm::printExportsTrie(const ObjectFile *o) {
  outs() << "Exports trie:\n";
  if (const MachOObjectFile *MachO = dyn_cast<MachOObjectFile>(o))
    printMachOExportsTrie(MachO);
  else {
    errs() << "This operation is only currently supported "
              "for Mach-O executable files.\n";
    return;
  }
}

void llvm::printRebaseTable(ObjectFile *o) {
  outs() << "Rebase table:\n";
  if (MachOObjectFile *MachO = dyn_cast<MachOObjectFile>(o))
    printMachORebaseTable(MachO);
  else {
    errs() << "This operation is only currently supported "
              "for Mach-O executable files.\n";
    return;
  }
}

void llvm::printBindTable(ObjectFile *o) {
  outs() << "Bind table:\n";
  if (MachOObjectFile *MachO = dyn_cast<MachOObjectFile>(o))
    printMachOBindTable(MachO);
  else {
    errs() << "This operation is only currently supported "
              "for Mach-O executable files.\n";
    return;
  }
}

void llvm::printLazyBindTable(ObjectFile *o) {
  outs() << "Lazy bind table:\n";
  if (MachOObjectFile *MachO = dyn_cast<MachOObjectFile>(o))
    printMachOLazyBindTable(MachO);
  else {
    errs() << "This operation is only currently supported "
              "for Mach-O executable files.\n";
    return;
  }
}

void llvm::printWeakBindTable(ObjectFile *o) {
  outs() << "Weak bind table:\n";
  if (MachOObjectFile *MachO = dyn_cast<MachOObjectFile>(o))
    printMachOWeakBindTable(MachO);
  else {
    errs() << "This operation is only currently supported "
              "for Mach-O executable files.\n";
    return;
  }
}

/// Dump the raw contents of the __clangast section so the output can be piped
/// into llvm-bcanalyzer.
void llvm::printRawClangAST(const ObjectFile *Obj) {
  if (outs().is_displayed()) {
    errs() << "The -raw-clang-ast option will dump the raw binary contents of "
              "the clang ast section.\n"
              "Please redirect the output to a file or another program such as "
              "llvm-bcanalyzer.\n";
    return;
  }

  StringRef ClangASTSectionName("__clangast");
  if (isa<COFFObjectFile>(Obj)) {
    ClangASTSectionName = "clangast";
  }

  Optional<object::SectionRef> ClangASTSection;
  for (auto Sec : ToolSectionFilter(*Obj)) {
    StringRef Name;
    if (auto NameOrErr = Sec.getName())
      Name = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());

    if (Name == ClangASTSectionName) {
      ClangASTSection = Sec;
      break;
    }
  }
  if (!ClangASTSection)
    return;

  StringRef ClangASTContents = unwrapOrError(
      ClangASTSection.getValue().getContents(), Obj->getFileName());
  outs().write(ClangASTContents.data(), ClangASTContents.size());
}

static void DumpObject(ObjectFile *o, const Archive *a = nullptr) {
  bool PrintAll =
      (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() > 0);
  // Avoid other output when using a raw option.
  if (PrintAll) {
    outs() << '\n';
    if (a)
      outs() << a->getFileName() << "(" << o->getFileName() << ")";
    else
      outs() << "; " << o->getFileName();
    outs() << ":\tfile format " << o->getFileFormatName() << "\n\n";
  }

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
      // Raise x86_64 relocatable binaries (.o files) is not supported.
      auto EType = Elf64LEObjFile->getELFFile()->getHeader()->e_type;
      if ((EType == ELF::ET_DYN) || (EType == ELF::ET_EXEC))
        DumpObject(o);
      else {
        errs() << "Raising x64 relocatable (.o) x64 binaries not supported\n";
        exit(1);
      }
    } else if (o->getArch() == Triple::arm)
      DumpObject(o);
    else {
      errs() << "No support to raise Binaries other than x64 and ARM\n";
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

  StringMap<cl::Option *> &Map = cl::getRegisteredOptions();

  // Unhide print-after-all option and place it in LLVMMCToLLCategory
  // Change its help string value appropriately
  assert(Map.count("print-after-all") > 0);
  Map["print-after-all"]->setHiddenFlag(cl::NotHidden);
  Map["print-after-all"]->addCategory(LLVMMCToLLCategory);
  Map["print-after-all"]->setDescription("Print IR after each raiser pass");

  cl::ParseCommandLineOptions(argc, argv, "MC to LLVM IR dumper\n");

  ToolName = argv[0];

  // Defaults to a.out if no filenames specified.
  if (InputFilenames.size() == 0)
    InputFilenames.push_back("a.out");

  // Disassemble contents of .text section.
  Disassemble = true;
  FilterSections.addValue(".text");

  std::for_each(InputFilenames.begin(), InputFilenames.end(), DumpInput);

  return EXIT_SUCCESS;
}
