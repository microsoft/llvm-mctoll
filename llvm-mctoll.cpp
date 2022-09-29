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

#include "EmitRaisedOutputPass.h"
#include "PeepholeOptimizationPass.h"
#include "Raiser/IncludedFileInfo.h"
#include "Raiser/MCInstOrData.h"
#include "Raiser/MachineFunctionRaiser.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm-mctoll.h"
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
#include "llvm/Option/Arg.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Option/Option.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
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

namespace {

using namespace llvm::opt; // for HelpHidden in Opts.inc
// custom Flag for opt::DriverFlag defined in the llvm/Option/Option.h
enum MyFlag { HelpSkipped = (1 << 4) };

enum ID {
  OPT_INVALID = 0, // This is not an option ID.
#define OPTION(PREFIX, NAME, ID, KIND, GROUP, ALIAS, ALIASARGS, FLAGS, PARAM,  \
               HELPTEXT, METAVAR, VALUES)                                      \
  OPT_##ID,
#include "Opts.inc"
#undef OPTION
};

#define PREFIX(NAME, VALUE) const char *const NAME[] = VALUE;
#include "Opts.inc"
#undef PREFIX

const opt::OptTable::Info InfoTable[] = {
#define OPTION(PREFIX, NAME, ID, KIND, GROUP, ALIAS, ALIASARGS, FLAGS, PARAM,  \
               HELPTEXT, METAVAR, VALUES)                                      \
  {                                                                            \
      PREFIX,      NAME,      HELPTEXT,                                        \
      METAVAR,     OPT_##ID,  opt::Option::KIND##Class,                        \
      PARAM,       FLAGS,     OPT_##GROUP,                                     \
      OPT_##ALIAS, ALIASARGS, VALUES},
#include "Opts.inc"
#undef OPTION
};

class MctollOptTable : public opt::OptTable {
public:
  MctollOptTable(const char *Usage, const char *Description)
      : OptTable(InfoTable), Usage(Usage), Description(Description) {
    setGroupedShortOptions(true);
  }

  void printHelp(StringRef Argv0, bool ShowHidden = false) const {
    Argv0 = sys::path::filename(Argv0);
    unsigned FlagsToExclude = HelpSkipped | (ShowHidden ? 0 : HelpHidden);
    opt::OptTable::printHelp(outs(), (Argv0 + Usage).str().c_str(), Description,
                             0, FlagsToExclude, ShowHidden);
    // TODO Replace this with OptTable API once it adds extrahelp support.
    outs() << "\nPass @FILE as argument to read options from FILE.\n";
  }

private:
  const char *Usage;
  const char *Description;
};

enum OutputFormatTy { OF_LL, OF_BC, OF_Null, OF_Unknown };

} // namespace

#define DEBUG_TYPE "mctoll"

static std::vector<std::string> InputFileNames;
static std::string OutputFilename;
std::string MCPU;
std::vector<std::string> MAttrs;
OutputFormatTy OutputFormat; // Output file type. Default is binary bitcode.
bool mctoll::Disassemble;
static bool MachOOpt;
static bool NoVerify;
std::string mctoll::TargetName;
std::string mctoll::TripleName;
std::string mctoll::SysRoot;
std::string mctoll::ArchName;
static std::string FilterConfigFileName;
std::vector<std::string> mctoll::FilterSections;

static uint64_t StartAddress;
static bool HasStartAddressFlag;
static uint64_t StopAddress = UINT64_MAX;
static bool HasStopAddressFlag;

/// String vector of include files to parse for external definitions
std::vector<std::string> mctoll::IncludeFileNames;
std::string mctoll::CompilationDBDir;

static bool PrintImmHex;

namespace {
static ManagedStatic<std::vector<std::string>> RunPassNames;

struct RunPassOption {
  // NOLINTNEXTLINE(misc-unconventional-assign-operator)
  auto operator=(const std::string &Val) const {
    if (Val.empty())
      return;
    SmallVector<StringRef, 8> PassNames;
    StringRef(Val).split(PassNames, ',', -1, false);
    for (auto PassName : PassNames)
      RunPassNames->push_back(std::string(PassName));
  }
};
} // namespace

namespace {
typedef std::function<bool(llvm::object::SectionRef const &)> FilterPredicate;

class SectionFilterIterator {
public:
  SectionFilterIterator(FilterPredicate P,
                        llvm::object::section_iterator const &I,
                        llvm::object::section_iterator const &E)
      : Predicate(std::move(P)), Iterator(I), End(E) {
    scanPredicate();
  }
  const llvm::object::SectionRef &operator*() const { return *Iterator; }
  SectionFilterIterator &operator++() {
    ++Iterator;
    scanPredicate();
    return *this;
  }
  bool operator!=(SectionFilterIterator const &Other) const {
    return Iterator != Other.Iterator;
  }

private:
  void scanPredicate() {
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

SectionFilter toolSectionFilter(llvm::object::ObjectFile const &O) {
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
        const auto *const COFFObj = dyn_cast<COFFObjectFile>(Obj);
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
      reportError(Obj->getFileName(), "Support for raising " +
                                          TheTriple.getArchName() +
                                          " not included");
    else
      error("Unsupported target " + TheTriple.getArchName());
  }

  // A few of opcodes in ARMv4 or ARMv5 are identified as ARMv6 opcodes,
  // so unify the triple Archs lower than ARMv6 to ARMv6 temporarily.
  if (TheTriple.getArchName() == "armv4t" ||
      TheTriple.getArchName() == "armv5te" ||
      TheTriple.getArchName() == "armv5" || TheTriple.getArchName() == "armv5t")
    TheTriple.setArchName("armv6");

  // Update the triple name and return the found target.
  TripleName = TheTriple.getTriple();
  return TheTarget;
}

static std::unique_ptr<ToolOutputFile> getOutputStream(StringRef InfileName) {
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
    case OF_LL:
      OutputFilename += "-dis.ll";
      break;
    // Just uses enum CGFT_ObjectFile represent llvm bitcode file type
    // provisionally.
    case OF_BC:
      OutputFilename += "-dis.bc";
      break;
    default:
      OutputFilename += ".null";
      break;
    }
  }

  // Decide if we need "binary" output.
  bool Binary = OutputFormat != OF_LL;

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

static bool addPass(PassManagerBase &PM, StringRef Argv0, StringRef PassName,
                    TargetPassConfig &TPC) {
  if (PassName == "none")
    return false;

  const PassRegistry *PR = PassRegistry::getPassRegistry();
  const PassInfo *PI = PR->getPassInfo(PassName);
  if (!PI) {
    errs() << Argv0 << ": run-pass " << PassName << " is not registered.\n";
    return true;
  }

  Pass *P;
  if (PI->getNormalCtor())
    P = PI->getNormalCtor()();
  else {
    errs() << Argv0 << ": cannot create pass: " << PI->getPassName() << "\n";
    return true;
  }
  std::string Banner = std::string("After ") + std::string(P->getPassName());
  PM.add(P);
  TPC.printAndVerify(Banner);

  return false;
}

bool mctoll::RelocAddressLess(RelocationRef A, RelocationRef B) {
  return A.getOffset() < B.getOffset();
}

namespace {
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
  uint8_t RefType = RelRef.getType();
  StringRef Res;
  int64_t Addend = 0;
  switch (Sec->sh_type) {
  default:
    return object_error::parse_failed;
  case ELF::SHT_REL: {
    // TODO: Read implicit addend from section data.
    break;
  }
  case ELF::SHT_RELA: {
    const Elf_Rela *ERela = Obj->getRela(Rel);
    Addend = ERela->r_addend;
    break;
  }
  }
  symbol_iterator SI = RelRef.getSymbol();
  const Elf_Sym *Symb = Obj->getSymbol(SI->getRawDataRefImpl());
  StringRef Target;
  if (Symb->getType() == ELF::STT_SECTION) {
    Expected<section_iterator> SymSI = SI->getSection();
    if (!SymSI)
      return errorToErrorCode(SymSI.takeError());
    const Elf_Shdr *SymSec = Obj->getSection((*SymSI)->getRawDataRefImpl());
    auto SecName = EF.getSectionName(SymSec);
    if (!SecName)
      return errorToErrorCode(SecName.takeError());
    Target = *SecName;
  } else {
    Expected<StringRef> SymName = Symb->getName(StrTab);
    if (!SymName)
      return errorToErrorCode(SymName.takeError());
    Target = *SymName;
  }
  switch (EF.getHeader()->e_machine) {
  case ELF::EM_X86_64:
    switch (RefType) {
    case ELF::R_X86_64_PC8:
    case ELF::R_X86_64_PC16:
    case ELF::R_X86_64_PC32: {
      std::string FmtBuf;
      raw_string_ostream Fmt(FmtBuf);
      Fmt << Target << (Addend < 0 ? "" : "+") << Addend << "-P";
      Fmt.flush();
      Result.append(FmtBuf.begin(), FmtBuf.end());
    } break;
    case ELF::R_X86_64_8:
    case ELF::R_X86_64_16:
    case ELF::R_X86_64_32:
    case ELF::R_X86_64_32S:
    case ELF::R_X86_64_64: {
      std::string FmtBuf;
      raw_string_ostream Fmt(FmtBuf);
      Fmt << Target << (Addend < 0 ? "" : "+") << Addend;
      Fmt.flush();
      Result.append(FmtBuf.begin(), FmtBuf.end());
    } break;
    default:
      Res = "Unknown";
    }
    break;
  case ELF::EM_LANAI:
  case ELF::EM_AVR:
  case ELF::EM_AARCH64: {
    std::string FmtBuf;
    raw_string_ostream Fmt(FmtBuf);
    Fmt << Target;
    if (Addend != 0)
      Fmt << (Addend < 0 ? "" : "+") << Addend;
    Fmt.flush();
    Result.append(FmtBuf.begin(), FmtBuf.end());
    break;
  }
  case ELF::EM_386:
  case ELF::EM_IAMCU:
  case ELF::EM_ARM:
  case ELF::EM_HEXAGON:
  case ELF::EM_MIPS:
  case ELF::EM_BPF:
  case ELF::EM_RISCV:
    Res = Target;
    break;
  default:
    Res = "Unknown";
  }
  if (Result.empty())
    Result.append(Res.begin(), Res.end());
  return std::error_code();
}

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

#define MODULE_RAISER(TargetName)                                              \
  extern "C" void register##TargetName##ModuleRaiser();
#include "Raisers.def"

static void initializeAllModuleRaisers() {
#define MODULE_RAISER(TargetName) register##TargetName##ModuleRaiser();
#include "Raisers.def"
}

static void disassembleObject(const ObjectFile *Obj, bool InlineRelocs) {
  if (StartAddress > StopAddress)
    error("Start address should be less than stop address");

  const Target *TheTarget = getTarget(Obj);

  // Package up features to be passed to target/subtarget
  SubtargetFeatures Features = Obj->getFeatures();
  if (MAttrs.size()) {
    for (unsigned Idx = 0; Idx != MAttrs.size(); ++Idx)
      Features.AddFeature(MAttrs[Idx]);
  }

  std::unique_ptr<const MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI)
    reportError(Obj->getFileName(),
                "no register info for target " + TripleName);

  MCTargetOptions MCOptions;
  // Set up disassembler.
  std::unique_ptr<const MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  if (!AsmInfo)
    reportError(Obj->getFileName(),
                "no assembly info for target " + TripleName);
  std::unique_ptr<const MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI)
    reportError(Obj->getFileName(),
                "no subtarget info for target " + TripleName);
  std::unique_ptr<const MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII)
    reportError(Obj->getFileName(),
                "no instruction info for target " + TripleName);
  MCContext Ctx(Triple(TripleName), AsmInfo.get(), MRI.get(), STI.get());

  std::unique_ptr<MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm)
    reportError(Obj->getFileName(), "no disassembler for target " + TripleName);

  std::unique_ptr<const MCInstrAnalysis> MIA(
      TheTarget->createMCInstrAnalysis(MII.get()));

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP)
    reportError(Obj->getFileName(),
                "no instruction printer for target " + TripleName);
  IP->setPrintImmHex(PrintImmHex);

  LLVMContext LlvmCtx;
  std::unique_ptr<TargetMachine> Target(
      TheTarget->createTargetMachine(TripleName, MCPU, Features.getString(),
                                     TargetOptions(), /* RelocModel */ None));
  assert(Target && "Could not allocate target machine!");

  LLVMTargetMachine &LlvmTgtMach = static_cast<LLVMTargetMachine &>(*Target);
  MachineModuleInfoWrapperPass *MachineModuleInfo =
      new MachineModuleInfoWrapperPass(&LlvmTgtMach);
  /* New Module instance with file name */
  Module M(Obj->getFileName(), LlvmCtx);
  /* Set datalayout of the module to be the same as LLVMTargetMachine */
  M.setDataLayout(Target->createDataLayout());
  MachineModuleInfo->doInitialization(M);
  // Initialize all module raisers that are supported and are part of current
  // LLVM build.
  initializeAllModuleRaisers();
  // Get the module raiser for Target of the binary being raised
  ModuleRaiser *MR = mctoll::getModuleRaiser(Target.get());
  assert((MR != nullptr) && "Failed to build module raiser");
  // Set data of module raiser
  MR->setModuleRaiserInfo(&M, Target.get(), &MachineModuleInfo->getMMI(),
                          MIA.get(), MII.get(), MRI.get(), IP.get(),
                          Obj, DisAsm.get());

  FunctionFilter *FuncFilter = MR->getFunctionFilter();
  if (!FilterConfigFileName.empty()) {
    if (!FuncFilter->readFilterFunctionConfigFile(FilterConfigFileName)) {
      dbgs() << "Unable to read function filter configuration file "
             << FilterConfigFileName << ". Ignoring\n";
    }
  }

  // Filtered sections list
  SmallVector<SectionRef, 1> FilteredSections;
  for (const SectionRef &Section : toolSectionFilter(*Obj)) {
    FilteredSections.push_back(Section);
  }

  // Load data
  MR->load(StartAddress, StopAddress, FilteredSections);

  // Add the pass manager
  legacy::PassManager PM;

  // Decide where to send the output.
  std::unique_ptr<ToolOutputFile> Out = getOutputStream(Obj->getFileName());
  if (!Out)
    return;

  // Keep the file created.
  Out->keep();

  auto *OS = &Out->os();

   LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*Target);

  CodeGenFileType OutputFileType;

  switch (OutputFormat) {
  case OF_LL:
    OutputFileType = CGFT_AssemblyFile;
    break;
  // Just uses enum CGFT_ObjectFile represent llvm bitcode file type
  // provisionally.
  case OF_BC:
    OutputFileType = CGFT_ObjectFile;
    break;
  default:
    OutputFileType = CGFT_Null;
    break;
  }

  if (RunPassNames->empty()) {
    TargetPassConfig &TPC = *LLVMTM.createPassConfig(PM);
    if (TPC.hasLimitedCodeGenPipeline()) {
      errs() << ToolName << ": run-pass cannot be used with "
             << TPC.getLimitedCodeGenPipelineReason(" and ") << ".\n";
      return;
    }

    TPC.setDisableVerify(NoVerify);
    PM.add(&TPC);
    PM.add(MachineModuleInfo);

    // Add optimizations prior to emitting the output file.
    PM.add(new PeepholeOptimizationPass());

    // Add print pass to emit ouptut file.
    PM.add(new EmitRaisedOutputPass(*OS, OutputFileType));

    TPC.printAndVerify("");
    for (const std::string &RunPassName : *RunPassNames) {
      if (addPass(PM, ToolName, RunPassName, TPC))
        return;
    }

    TPC.setInitialized();
  } else if (Target->addPassesToEmitFile(
                 PM, *OS, nullptr, /* no dwarf output file stream*/
                 OutputFileType, NoVerify, MachineModuleInfo)) {
    outs() << ToolName << "run system pass!\n";
  }

  PM.run(M);
}

static void dumpObject(ObjectFile *O, const Archive *A = nullptr) {
  // Avoid other output when using a raw option.
  LLVM_DEBUG(dbgs() << '\n');
  if (A)
    LLVM_DEBUG(dbgs() << A->getFileName() << "(" << O->getFileName() << ")");
  else
    LLVM_DEBUG(dbgs() << "; " << O->getFileName());
  LLVM_DEBUG(dbgs() << ":\tfile format " << O->getFileFormatName() << "\n\n");

  assert(Disassemble && "Disassemble not set!");
  disassembleObject(O, /* InlineRelocations */ false);
}

static void dumpObject(const COFFImportFile *I, const Archive *A) {
  assert(false &&
         "This function needs to be deleted and is not expected to be called.");
}

/// @brief Dump each object file in \a a;
static void dumpArchive(const Archive *A) {
  Error Err = Error::success();
  for (auto &C : A->children(Err)) {
    Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
    if (!ChildOrErr) {
      if (auto E = isNotObjectErrorInvalidFileType(ChildOrErr.takeError()))
        reportError(std::move(E), A->getFileName(), C);
      continue;
    }
    if (ObjectFile *O = dyn_cast<ObjectFile>(&*ChildOrErr.get()))
      dumpObject(O, A);
    else if (COFFImportFile *I = dyn_cast<COFFImportFile>(&*ChildOrErr.get()))
      dumpObject(I, A);
    else
      reportError(errorCodeToError(object_error::invalid_file_type),
                  A->getFileName());
  }
  if (Err)
    reportError(std::move(Err), A->getFileName());
}

/// @brief Open file and figure out how to dump it.
static void dumpInput(StringRef File) {
  // If we are using the Mach-O specific object file parser, then let it parse
  // the file and process the command line options.  So the -arch flags can
  // be used to select specific slices, etc.
  if (MachOOpt) {
    parseInputMachO(File);
    return;
  }

  // Attempt to open the binary.
  Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(File);
  if (!BinaryOrErr)
    reportError(BinaryOrErr.takeError(), File);
  Binary &Binary = *BinaryOrErr.get().getBinary();

  if (Archive *A = dyn_cast<Archive>(&Binary))
    dumpArchive(A);
  else if (ObjectFile *O = dyn_cast<ObjectFile>(&Binary)) {
    if (O->getArch() == Triple::x86_64) {
      const ELF64LEObjectFile *Elf64LEObjFile = dyn_cast<ELF64LEObjectFile>(O);
      if (Elf64LEObjFile == nullptr) {
        errs() << "\n\n*** " << File << " : Not 64-bit ELF binary\n"
               << "*** Currently only 64-bit ELF binary raising supported.\n"
               << "*** Please consider contributing support to raise other "
                  "binary formats. Thanks!\n";
        exit(1);
      }
      // Raise x86_64 relocatable binaries (.o files) is not supported.
      auto EType = Elf64LEObjFile->getELFFile().getHeader().e_type;
      if ((EType == ELF::ET_DYN) || (EType == ELF::ET_EXEC))
        dumpObject(O);
      else {
        errs() << "Raising x64 relocatable (.o) x64 binaries not supported\n";
        exit(1);
      }
    } else if (O->getArch() == Triple::arm)
      dumpObject(O);
    else {
      errs() << "\n\n*** No support to raise Binaries other than x64 and ARM\n"
             << "*** Please consider contributing support to raise other "
                "ISAs. Thanks!\n";
      exit(1);
    }
  } else
    reportError(errorCodeToError(object_error::invalid_file_type), File);
}

[[noreturn]] static void reportCmdLineError(const Twine &Message) {
  WithColor::error(errs(), ToolName) << Message << "\n";
  exit(1);
}

template <typename T>
static void parseIntArg(const llvm::opt::InputArgList &InputArgs, int ID,
                        T &Value) {
  if (const opt::Arg *A = InputArgs.getLastArg(ID)) {
    StringRef V(A->getValue());
    if (!llvm::to_integer(V, Value, 0)) {
      reportCmdLineError(A->getSpelling() +
                         ": expected a non-negative integer, but got '" + V +
                         "'");
    }
  }
}

static void invalidArgValue(const opt::Arg *A) {
  reportCmdLineError("'" + StringRef(A->getValue()) +
                     "' is not a valid value for '" + A->getSpelling() + "'");
}

static std::vector<std::string>
commaSeparatedValues(const llvm::opt::InputArgList &InputArgs, int ID) {
  std::vector<std::string> Values;
  for (StringRef Value : InputArgs.getAllArgValues(ID)) {
    llvm::SmallVector<StringRef, 2> SplitValues;
    llvm::SplitString(Value, SplitValues, ",");
    for (StringRef SplitValue : SplitValues)
      Values.push_back(SplitValue.str());
  }
  return Values;
}

static void parseOptions(const llvm::opt::InputArgList &InputArgs) {
  llvm::DebugFlag = InputArgs.hasArg(OPT_debug);
  Disassemble = InputArgs.hasArg(OPT_raise);
  FilterConfigFileName =
      InputArgs.getLastArgValue(OPT_filter_functions_file_EQ).str();
  MCPU = InputArgs.getLastArgValue(OPT_mcpu_EQ).str();
  MAttrs = commaSeparatedValues(InputArgs, OPT_mattr_EQ);
  FilterSections = InputArgs.getAllArgValues(OPT_section_EQ);
  parseIntArg(InputArgs, OPT_start_address_EQ, StartAddress);
  HasStartAddressFlag = InputArgs.hasArg(OPT_start_address_EQ);
  parseIntArg(InputArgs, OPT_stop_address_EQ, StopAddress);
  HasStopAddressFlag = InputArgs.hasArg(OPT_stop_address_EQ);
  TargetName = InputArgs.getLastArgValue(OPT_target_EQ).str();
  SysRoot = InputArgs.getLastArgValue(OPT_sysyroot_EQ).str();
  OutputFilename = InputArgs.getLastArgValue(OPT_outfile_EQ).str();

  InputFileNames = InputArgs.getAllArgValues(OPT_INPUT);
  if (InputFileNames.empty())
    reportCmdLineError("no input file");

  IncludeFileNames = InputArgs.getAllArgValues(OPT_include_file_EQ);
  std::string IncludeFileNames2 =
      InputArgs.getLastArgValue(OPT_include_files_EQ).str();
  if (!IncludeFileNames2.empty()) {
    SmallVector<StringRef, 8> FNames;
    StringRef(IncludeFileNames2).split(FNames, ',', -1, false);
    for (auto N : FNames)
      IncludeFileNames.push_back(std::string(N));
  }

  if (const opt::Arg *A = InputArgs.getLastArg(OPT_output_format_EQ)) {
    OutputFormat = StringSwitch<OutputFormatTy>(A->getValue())
                       .Case("ll", OF_LL)
                       .Case("BC", OF_BC)
                       .Case("Null", OF_Null)
                       .Default(OF_Unknown);
    if (OutputFormat == OF_Unknown)
      invalidArgValue(A);
  }
}

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);

  // parse command line
  BumpPtrAllocator A;
  StringSaver Saver(A);
  MctollOptTable Tbl(" [options] <input object files>", "MC to LLVM IR raiser");
  ToolName = argv[0];
  opt::InputArgList Args =
      Tbl.parseArgs(argc, argv, OPT_UNKNOWN, Saver, [&](StringRef Msg) {
        error(Msg);
        exit(1);
      });
  if (Args.size() == 0 || Args.hasArg(OPT_help)) {
    Tbl.printHelp(ToolName);
    return 0;
  }
  if (Args.hasArg(OPT_help_hidden)) {
    Tbl.printHelp(ToolName, /*ShowHidden=*/true);
    return 0;
  }

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  if (Args.hasArg(OPT_version)) {
    cl::PrintVersionMessage();
    outs() << '\n';
    TargetRegistry::printRegisteredTargetsForVersion(outs());
    return 0;
  }

  parseOptions(Args);

  // Set appropriate bug report message
  llvm::setBugReportMsg(
      "\n*** Please submit an issue at "
      "https://github.com/microsoft/llvm-mctoll"
      "\n*** along with a back trace and a reproducer, if possible.\n");

  // Create a string vector with copy of input file as positional arguments
  // that would be erased as part of include file parsing done by
  // clang::tooling::CommonOptionsParser invoked in
  // getExternalFunctionPrototype().
  std::vector<string> InputFNames;
  for (auto FName : InputFileNames) {
    InputFNames.emplace_back(FName);
  }

  // Stash output file name as well since it would also be reset during parsing
  // done by clang::tooling::CommonOptionsParser invoked in
  // getExternalFunctionPrototype().
  auto OF = OutputFilename;

  if (!IncludeFileNames.empty()) {
    if (!IncludedFileInfo::getExternalFunctionPrototype(IncludeFileNames,
                                                        TargetName,
                                                        SysRoot)) {
      dbgs() << "Unable to read external function prototype. Ignoring\n";
    }
  }
  // Restore stashed OutputFileName
  OutputFilename = OF;
  // Disassemble contents of .text section.
  Disassemble = true;
  FilterSections.push_back(".text");

  llvm::setCurrentDebugType(DEBUG_TYPE);
  std::for_each(InputFNames.begin(), InputFNames.end(), dumpInput);

  return EXIT_SUCCESS;
}
#undef DEBUG_TYPE
