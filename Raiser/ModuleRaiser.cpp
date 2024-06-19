//===-- ModuleRaiser.cpp ------------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ModuleRaiser.h"
#include "MachineFunctionRaiser.h"
#include "MachineInstructionRaiser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/WithColor.h"


#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::mctoll;

StringRef mctoll::ToolName;

void mctoll::error(std::error_code EC) {
  if (!EC)
    return;

  errs() << ToolName << ": error reading file: " << EC.message() << ".\n";
  errs().flush();
  exit(1);
}

void mctoll::error(Error E) {
  if (!E)
    return;
  WithColor::error(errs(), ToolName) << toString(std::move(E));
  exit(1);
}

[[noreturn]] void mctoll::error(Twine Message) {
  errs() << ToolName << ": " << Message << ".\n";
  errs().flush();
  exit(1);
}

[[noreturn]] void mctoll::reportError(StringRef File, Twine Message) {
  WithColor::error(errs(), ToolName)
      << "'" << File << "': " << Message << ".\n";
  exit(1);
}

[[noreturn]] void mctoll::reportError(Error E, StringRef File) {
  assert(E);
  std::string Buf;
  raw_string_ostream OS(Buf);
  logAllUnhandledErrors(std::move(E), OS);
  OS.flush();
  WithColor::error(errs(), ToolName) << "'" << File << "': " << Buf;
  exit(1);
}

[[noreturn]] void mctoll::reportError(Error E, StringRef ArchiveName,
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

[[noreturn]] void mctoll::reportError(Error E, StringRef ArchiveName,
                                       const object::Archive::Child &C,
                                       StringRef ArchitectureName) {
  Expected<StringRef> NameOrErr = C.getName();
  // TODO: if we have a error getting the name then it would be nice to print
  // the index of which archive member this is and or its offset in the
  // archive instead of "???" as the name.
  if (!NameOrErr) {
    consumeError(NameOrErr.takeError());
    reportError(std::move(E), ArchiveName, "???", ArchitectureName);
  } else
    reportError(std::move(E), ArchiveName, NameOrErr.get(), ArchitectureName);
}

// raiser registry context
static SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;

bool mctoll::isSupportedArch(Triple::ArchType Arch) {
  for (auto *M : ModuleRaiserRegistry)
    if (M->getArchType() == Arch)
      return true;

  return false;
}

ModuleRaiser *mctoll::getModuleRaiser(const TargetMachine *TM) {
  ModuleRaiser *MR = nullptr;
  auto Arch = TM->getTargetTriple().getArch();
  for (auto *M : ModuleRaiserRegistry)
    if (M->getArchType() == Arch) {
      MR = M;
      break;
    }
  assert(nullptr != MR && "This arch has not yet supported for raising!\n");
  return MR;
}

void mctoll::registerModuleRaiser(ModuleRaiser *M) {
  ModuleRaiserRegistry.push_back(M);
}

Function *ModuleRaiser::getRaisedFunctionAt(uint64_t Index) const {
  int64_t TextSecAddr = getTextSectionAddress();
  for (auto *MFR : MFRaiserVector)
    if ((MFR->getMCInstRaiser()->getFuncStart() + TextSecAddr) == Index)
      return MFR->getRaisedFunction();

  return nullptr;
}

const RelocationRef *ModuleRaiser::getDynRelocAtOffset(uint64_t Loc) const {
  if (DynRelocs.empty())
    return nullptr;

  auto RelocIter = std::find_if(
      DynRelocs.begin(), DynRelocs.end(),
      [Loc](const RelocationRef &A) -> bool { return (A.getOffset() == Loc); });
  if (RelocIter != DynRelocs.end())
    return &(*RelocIter);

  return nullptr;
}

// Return relocation whose offset is in the range [Index, Index+Size)
const RelocationRef *ModuleRaiser::getTextRelocAtOffset(uint64_t Index,
                                                        uint64_t Size) const {
  if (TextRelocs.empty())
    return nullptr;

  auto RelocIter = std::find_if(TextRelocs.begin(), TextRelocs.end(),
                                [Index, Size](const RelocationRef &A) -> bool {
                                  return ((A.getOffset() >= Index) &&
                                          (A.getOffset() < (Index + Size)));
                                });
  if (RelocIter != TextRelocs.end())
    return &(*RelocIter);

  return nullptr;
}

Function *ModuleRaiser::getCalledFunctionUsingTextReloc(uint64_t Loc,
                                                        uint64_t Size) const {
  // Find the text relocation with offset in the range [Loc, Loc+Size)
  const RelocationRef *TextReloc = getTextRelocAtOffset(Loc, Loc + Size);
  if (TextReloc != nullptr) {
    Expected<StringRef> Sym = TextReloc->getSymbol()->getName();
    assert(Sym && "Failed to find call target symbol");
    for (auto *MFR : MFRaiserVector) {
      Function *F = MFR->getRaisedFunction();
      assert(F && "Unexpected null function pointer encountered");
      if (Sym->equals(F->getName()))
        return F;
    }
  }
  return nullptr;
}

bool ModuleRaiser::runMachineFunctionPasses() {
  bool Success = true;

  for (auto *MFR : MFRaiserVector) {
    LLVM_DEBUG(dbgs() << "Function: "
                      << MFR->getMachineFunction().getName().data() << "\n");
    LLVM_DEBUG(dbgs() << "Parsed MCInst List\n");
    LLVM_DEBUG(MFR->getMCInstRaiser()->dump(MIP, " ", MRI));
  }

  // For each of the functions, run passes to set up for instruction raising.
  for (auto *MFR : MFRaiserVector) {
    // 1. Build CFG
    MCInstRaiser *MCIR = MFR->getMCInstRaiser();
    // Populates the MachineFunction with CFG.
    MCIR->buildCFG(MFR->getMachineFunction(), MIA, MII);
  }

  // Construct function prototypes for each of the MachineFunctions.
  // Knowing the function prototypes prior to raising the instructions
  // facilitates raising of call instructions whose targets are within
  // the current module.
  // Iterate the MachineFunctions twice to determine the prototypes of functions
  // that might call those whose prototypes were not yet constructed.
  bool AllPrototypesConstructed;
  const int IterCount = 2;
  for (int Idx = 0; Idx < IterCount; Idx++) {
    AllPrototypesConstructed = true;
    for (auto *MFR : MFRaiserVector) {
      LLVM_DEBUG(dbgs() << "Build Prototype for : "
                        << MFR->getMachineFunction().getName().data() << "\n");
      Function *RF = MFR->getRaisedFunction();
      if (RF == nullptr) {
        FunctionType *FT =
            MFR->getMachineInstrRaiser()->getRaisedFunctionPrototype();
        AllPrototypesConstructed |= (FT != nullptr);
      }
    }
    LLVM_DEBUG(dbgs() << "Raised Function Prototypes: \n");
    LLVM_DEBUG({
      for (auto MFR : MFRaiserVector) {
        MFR->getRaisedFunction()->dump();
      }
    });
  }
  assert(AllPrototypesConstructed && "Failed to construct all prototypes");
  // Run instruction raiser passes.
  for (auto *MFR : MFRaiserVector)
    Success |= MFR->runRaiserPasses();

  return Success;
}

/// Get the MachineFunction associated with the placeholder
/// function corresponding to raised function.
MachineFunction *ModuleRaiser::getMachineFunction(Function *RF) {
  auto V = PlaceholderRaisedFunctionMap.find(RF);
  assert(V != PlaceholderRaisedFunctionMap.end() &&
         "Failed to find place-holder function");
  return MMI->getMachineFunction(*V->getSecond());
}

bool ModuleRaiser::collectTextSectionRelocs(const SectionRef &TextSec) {
  // Assuming only one .text section in the binary
  assert(TextSectionIndex == -1 &&
         "Relocations for .text section already collected");
  TextSectionIndex = TextSec.getIndex();
  // Find the section whose relocated section index is TextSecIndex.
  // That section is the one with relocations corresponding to the
  // section with index TextSecIndex.
  for (const SectionRef &CandRelocSection : Obj->sections()) {
    Expected<section_iterator> RelSecOrErr =
        CandRelocSection.getRelocatedSection();
    if (!RelSecOrErr) {
      return false;
    }
    section_iterator RelocatedSecIter = *RelSecOrErr;
    // If the CandRelocSection has a corresponding relocated section
    if (RelocatedSecIter != Obj->section_end()) {
      // If the corresponding relocated section is TextSec, CandRelocSection
      // is the section with relocation information for TextSec.
      if (RelocatedSecIter->getIndex() == (uint64_t)TextSectionIndex) {
        for (const RelocationRef &Reloc : CandRelocSection.relocations())
          TextRelocs.push_back(Reloc);

        // Sort the relocations
        std::sort(TextRelocs.begin(), TextRelocs.end(),
                  [](const RelocationRef &A, const RelocationRef &B) -> bool {
                    return A.getOffset() < B.getOffset();
                  });
        break;
      }
    }
  }
  return true;
}

// Return text section address; or -1 if text section is not found
int64_t ModuleRaiser::getTextSectionAddress() const {
  if (!Obj->isELF())
    return -1;

  assert(TextSectionIndex >= 0 && "Unexpected negative index of text section");
  for (SectionRef Sec : Obj->sections())
    if (Sec.getIndex() == (unsigned)TextSectionIndex)
      return Sec.getAddress();

  llvm_unreachable("Failed to locate text section.");
}

// Change return type of TargetFunc and update the change in module and
// MachineFunctionRaiser of TargetFunc. The new function is the same in every
// respect except with specified return type. Return true to indicate a change;
// false otherwise.
bool ModuleRaiser::changeRaisedFunctionReturnType(Function *TargetFunc,
                                                  Type *NewRetTy) {
  Type *TgtFuncRetTy = TargetFunc->getReturnType();
  // Was the change affected?
  bool Changed = false;

  // Get the MachineFunction of TargetFunc
  MachineFunctionRaiser *TargetFuncMFRaiser = nullptr;
  for (auto *MIR : MFRaiserVector) {
    if (MIR->getRaisedFunction() == TargetFunc) {
      TargetFuncMFRaiser = MIR;
      break;
    }
  }

  assert(TargetFuncMFRaiser != nullptr &&
         "Expect to find MachineFunction raiser for return type change");

  if (TgtFuncRetTy != NewRetTy) {
    std::vector<Type *> ArgTypes;
    for (const Argument &I : TargetFunc->args())
      ArgTypes.push_back(I.getType());

    // Create function with new signature and clone the old body into it.
    FunctionType *NewFT = FunctionType::get(NewRetTy, ArgTypes, false);
    Function *NewF =
        Function::Create(NewFT, TargetFunc->getLinkage(),
                         TargetFunc->getAddressSpace(), TargetFunc->getName());
    NewF->copyAttributesFrom(TargetFunc);
    NewF->setSubprogram(TargetFunc->getSubprogram());

    TargetFunc->getParent()->getFunctionList().insert(TargetFunc->getIterator(),
                                                      NewF);
    NewF->takeName(TargetFunc);

    NewF->getBasicBlockList().splice(NewF->begin(),
                                     TargetFunc->getBasicBlockList());
    // Loop over the argument list, transferring uses of the old arguments over
    // to the new arguments, also transferring over the names as well.
    for (Function::arg_iterator I = TargetFunc->arg_begin(),
                                E = TargetFunc->arg_end(),
                                I2 = NewF->arg_begin();
         I != E; ++I) {
      // Move the name and users over to the new version.
      I->replaceAllUsesWith(&*I2);
      I2->takeName(&*I);
      ++I2;
    }
    // Change the function type used in any of the users of this function to
    // match that for NewF.
    for (auto *U : TargetFunc->getFunction().users()) {
      if (auto *C = dyn_cast<CallInst>(U)) {
        CallInst *TgtFuncCall = const_cast<CallInst *>(C);
        SmallVector<Instruction *, 8> TgtFuncCallsToDelete;
        // If changing to a function type with void return type, the original
        // call instruction's return value should have no uses. Remove its name
        if (NewRetTy->isVoidTy()) {
          if (!TgtFuncCall->uses().empty()) {
            // If there are users, they are just pro-active cast
            // instructions
            for (auto *RetUsr : TgtFuncCall->users()) {
              if (CastInst *CI = dyn_cast<CastInst>(RetUsr)) {
                assert((CI->uses().empty()) &&
                       "Unexpected uses of a void return value");
                TgtFuncCallsToDelete.push_back(CI);
              } else
                assert(false && "Unhandled use of return value");
            }
          }
          TgtFuncCall->setName("");
        }
        TgtFuncCall->mutateFunctionType(NewFT);
        TgtFuncCall->setCalledFunction(NewF);

        for (Instruction *I : TgtFuncCallsToDelete) {
          I->eraseFromParent();
        }
        // If TgtFuncCall is a tail call, modify return instruction in the
        // return block of the Function containing TgtFuncCall according to
        // NewRetTy. Note that all functions have a single return block since
        // UnifyFunctionExitNodes pass should have run on TgtFuncCallerFunc
        // after its construction except the current function.
        if (TgtFuncCall->isTailCall()) {
          LLVMContext &Ctx(TargetFunc->getContext());
          Function *TgtFuncCallerFunc = TgtFuncCall->getParent()->getParent();
          for (BasicBlock &BB : *TgtFuncCallerFunc) {
            if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
              Value *NewRetVal = (NewRetTy->isVoidTy()) ? nullptr : TgtFuncCall;
              // If NewRetTy is void, NewRetVal is void else it is OrigCall
              // create and insert a new return instruction returning NewRetVal
              ReturnInst::Create(Ctx, NewRetVal, RI);
              // delete original ret instruction.
              RI->eraseFromParent();
              // No further search for blocks with return needed since the pass
              // UnifyFunctionExitNodes should have run on OrigCallFunc after
              // its construction - unless the TgtFuncCallerFunc is the
              // TargetFunc, in which case, the pass has not been run yet. Hence
              // all return instructions need to be changed.
              if (TgtFuncCallerFunc != TargetFunc)
                break;
            }
          }
          // Change the return type of TgtFuncCallerFunc since this is a tail
          // call if it is not changed in the current modification.
          // NOTE: This is a recursive call. Since the return type being changed
          // i.e., NewRetTy, is the same for all the target functions, the
          // recursive call will reach a  fix-point and will terminate.
          changeRaisedFunctionReturnType(TgtFuncCallerFunc, NewRetTy);
        }
      }
    }
    // Delete old function signature from function list
    TargetFunc->getParent()->getFunctionList().remove(
        TargetFunc->getIterator());
    // Update raised function
    TargetFuncMFRaiser->setRaisedFunction(NewF);
    Changed = true;
  }
  return Changed;
}

static bool isArmElf(const ObjectFile *Obj) {
  return (Obj->isELF() &&
          (Obj->getArch() == Triple::aarch64 ||
           Obj->getArch() == Triple::aarch64_be ||
           Obj->getArch() == Triple::arm || Obj->getArch() == Triple::armeb ||
           Obj->getArch() == Triple::thumb ||
           Obj->getArch() == Triple::thumbeb));
}

static bool isAFunctionSymbol(const ObjectFile *Obj, SymbolInfoTy &Symbol) {
  if (Obj->isELF()) {
    return (Symbol.Type == ELF::STT_FUNC);
  }
  return false;
}

static uint8_t getElfSymbolType(const ObjectFile *Obj, const SymbolRef &Sym) {
  assert(Obj->isELF());
  auto SymbImpl = Sym.getRawDataRefImpl();
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj)) {
    auto SymbOrErr = Elf32LEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      reportError(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj)) {
    auto SymbOrErr = Elf64LEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      reportError(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj)) {
    auto SymbOrErr = Elf32BEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      reportError(SymbOrErr.takeError(), "ELF32 symbol not found");
    return SymbOrErr.get()->getType();
  }
  if (auto *Elf64BEObj = dyn_cast<ELF64BEObjectFile>(Obj)) {
    auto SymbOrErr = Elf64BEObj->getSymbol(SymbImpl);
    if (!SymbOrErr)
      reportError(SymbOrErr.takeError(), "ELF32 symbol not found");
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
      reportError(AddressOrErr.takeError(), Obj->getFileName());
    uint64_t Address = *AddressOrErr;

    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      reportError(Name.takeError(), Obj->getFileName());
    if (Name->empty())
      continue;

    Expected<section_iterator> SectionOrErr = Symbol.getSection();
    if (!SectionOrErr)
      reportError(SectionOrErr.takeError(), Obj->getFileName());
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
  else if (auto *Elf64BEObj = dyn_cast<ELF64BEObjectFile>(Obj))
    addDynamicElfSymbols(Elf64BEObj, AllSymbols);
  else
    llvm_unreachable("Unsupported binary format");
}

/// Load data from object file.
void ModuleRaiser::load(uint64_t StartAddress, uint64_t StopAddress,
                        SmallVector<SectionRef, 1> &FilteredSections) {
  // Collect dynamic relocations.
  collectDynamicRelocations();

  // Create a mapping, RelocSecs = SectionRelocMap[S], where sections
  // in RelocSecs contain the relocations for section S.
  std::map<SectionRef, SmallVector<SectionRef, 1>> SectionRelocMap;
  for (const SectionRef &Section : FilteredSections) {
    Expected<section_iterator> SecOrErr = Section.getRelocatedSection();
    if (!SecOrErr) {
      break;
    }
    section_iterator Sec2 = *SecOrErr;
    if (Sec2 != Obj->section_end())
      SectionRelocMap[*Sec2].push_back(Section);
  }

  // Create a mapping from virtual address to symbol name. This is used to
  // pretty print the symbols while disassembling.
  std::map<SectionRef, SectionSymbolsTy> AllSymbols;
  for (const SymbolRef &Symbol : Obj->symbols()) {
    Expected<uint64_t> AddressOrErr = Symbol.getAddress();
    if (!AddressOrErr)
      reportError(AddressOrErr.takeError(), Obj->getFileName());
    uint64_t Address = *AddressOrErr;

    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      reportError(Name.takeError(), Obj->getFileName());
    if (Name->empty())
      continue;

    Expected<section_iterator> SectionOrErr = Symbol.getSection();
    if (!SectionOrErr)
      reportError(SectionOrErr.takeError(), Obj->getFileName());
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

  // Sort all the symbols, this allows us to use a simple binary search to find
  // a symbol near an address.
  for (std::pair<const SectionRef, SectionSymbolsTy> &SecSyms : AllSymbols)
    array_pod_sort(SecSyms.second.begin(), SecSyms.second.end());

  for (const SectionRef &Section : FilteredSections) {
    if ((!Section.isText() || Section.isVirtual()))
      continue;

    uint64_t SectionAddr = Section.getAddress();
    uint64_t SectSize = Section.getSize();
    if (!SectSize)
      return;

    // Get the list of all the symbols in this section.
    SectionSymbolsTy &Symbols = AllSymbols[Section];

    // If the section has no symbol at the start, just insert a dummy one.
    StringRef DummyName;
    if (Symbols.empty() || Symbols[0].Addr != 0) {
      Symbols.insert(
          Symbols.begin(),
          SymbolInfoTy(SectionAddr, DummyName,
                       Section.isText() ? ELF::STT_FUNC : ELF::STT_OBJECT));
    }

    StringRef SectionName;
    if (auto NameOrErr = Section.getName())
      SectionName = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());

    SmallString<40> Comments;
    raw_svector_ostream CommentStream(Comments);

    StringRef BytesStr =
        unwrapOrError(Section.getContents(), Obj->getFileName());
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(BytesStr.data()),
                            BytesStr.size());

    uint64_t Size;
    uint64_t Index;

    // Create a mapping from virtual address to section.
    std::vector<std::pair<uint64_t, SectionRef>> SectionAddresses;
    for (SectionRef Sec : Obj->sections())
      SectionAddresses.emplace_back(Sec.getAddress(), Sec);
    array_pod_sort(SectionAddresses.begin(), SectionAddresses.end());

    // Linked executables (.exe and .dll files) typically don't include a real
    // symbol table, but they might contain an export table.
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

    // Build a map of relocations (if they exist in the binary) of text
    // section whose instructions are being raised.
    collectTextSectionRelocs(Section);

    // Set used to record all branch targets of a function.
    std::set<uint64_t> BranchTargetSet;
    MachineFunctionRaiser *CurMFRaiser = nullptr;

    // Disassemble symbol by symbol and fill MR->MFRaiserVector by
    // MachineFunctionRaiser for each function
    LLVM_DEBUG(dbgs() << "BEGIN Disassembly of Functions in Section : "
                      << SectionName.data() << "\n");
    for (unsigned SI = 0, SSize = Symbols.size(); SI != SSize; ++SI) {
      uint64_t Start = Symbols[SI].Addr - SectionAddr;
      // The end is either the section end or the beginning of the next
      // symbol.
      uint64_t End =
          (SI == SSize - 1) ? SectSize : Symbols[SI + 1].Addr - SectionAddr;
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
        if (Symbols[SI].Type == ELF::STT_AMDGPU_HSA_KERNEL) {
          // skip amd_kernel_code_t at the begining of kernel symbol (256 bytes)
          Start += 256;
        }
        if (SI == SSize - 1 ||
            Symbols[SI + 1].Type == ELF::STT_AMDGPU_HSA_KERNEL) {
          // cut trailing zeroes at the end of kernel
          // cut up to 256 bytes
          const uint64_t EndAlign = 256;
          const auto Limit = End - (std::min)(EndAlign, End - Start);
          while (End > Limit && *reinterpret_cast<const support::ulittle32_t *>(
                                    &Bytes[End - 4]) == 0)
            End -= 4;
        }
      }

      if (isAFunctionSymbol(Obj, Symbols[SI])) {
        auto &SymStr = Symbols[SI].Name;

        // Check the symbol name by the function filter.
        if (!FFT->checkFunctionFilter(SymStr, Start))
          continue;

        // If Symbol is in the CRTSymbol list return this is a symbol of a
        // function we are not interested in disassembling and raising.
        if (FFT->isCRTFunction(Obj, SymStr))
          continue;

        // Note that since LLVM infrastructure was built to be used to build a
        // conventional compiler pipeline, MachineFunction is built well after
        // Function object was created and populated fully. Hence, creation of
        // a Function object is necessary to build MachineFunction.
        // However, in a raiser, we are conceptually walking the traditional
        // compiler pipeline backwards. So we build MachineFunction from
        // the binary before building Function object. Given the dependency,
        // build a placeholder Function object to allow for building the
        // MachineFunction object.
        // This Function object is NOT populated when raising MachineFunction
        // abstraction of the binary function. Instead, a new Function is
        // created using the LLVMContext and name of this Function object.
        FunctionType *FTy = FunctionType::get(Type::getVoidTy(M->getContext()), false);
        StringRef FunctionName(Symbols[SI].Name);
        // Strip leading underscore if the binary is MachO
        if (Obj->isMachO()) {
          FunctionName.consume_front("_");
        }
        Function *Func = Function::Create(FTy, GlobalValue::ExternalLinkage,
                                          FunctionName, M);

        // New function symbol encountered. Record all targets collected to
        // current MachineFunctionRaiser before we start parsing the new
        // function bytes.
        CurMFRaiser = getCurrentMachineFunctionRaiser();
        for (auto TargetIdx : BranchTargetSet) {
          assert(CurMFRaiser != nullptr &&
                 "Encountered uninitialized MachineFunction raiser object");
          CurMFRaiser->getMCInstRaiser()->addTarget(TargetIdx);
        }

        // Clear the set used to record all branch targets of this function.
        BranchTargetSet.clear();
        // Create a new MachineFunction raiser
        CurMFRaiser =
            CreateAndAddMachineFunctionRaiser(Func, this, Start, End);
        LLVM_DEBUG(dbgs() << "\nFunction " << Symbols[SI].Name << ":\n");
      } else {
        // Continue using to the most recent MachineFunctionRaiser
        // Get current MachineFunctionRaiser
        CurMFRaiser = getCurrentMachineFunctionRaiser();
        // assert(curMFRaiser != nullptr && "Current Machine Function Raiser not
        // initialized");
        if (CurMFRaiser == nullptr) {
          // At this point in the instruction stream, we do not have a function
          // symbol to which the bytes being parsed can be made part of. So skip
          // parsing the bytes of this symbol.
          continue;
        }

        // Adjust function end to represent the addition of the content of the
        // current symbol. This represents a situation where we have discovered
        // bytes (most likely data bytes) that belong to the most recent
        // function being parsed.
        MCInstRaiser *InstRaiser = CurMFRaiser->getMCInstRaiser();
        if (InstRaiser->getFuncEnd() < End) {
          assert(InstRaiser->adjustFuncEnd(End) &&
                 "Unable to adjust function end value");
        }
      }

      // Get the associated MCInstRaiser
      MCInstRaiser *InstRaiser = CurMFRaiser->getMCInstRaiser();

      // Start new basic block at the symbol.
      BranchTargetSet.insert(Start);

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
        if (isArmElf(Obj) && Symbols[SI].Type != ELF::STT_OBJECT) {
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
                  const auto *const Word =
                      reinterpret_cast<const support::ulittle32_t *>(
                          Bytes.data() + Index);
                  Data = *Word;
                } else {
                  const auto *const Word =
                      reinterpret_cast<const support::ubig32_t *>(Bytes.data() +
                                                                  Index);
                  Data = *Word;
                }
                InstRaiser->addMCInstOrData(Index, Data);
              } else if (Index + 2 <= End) {
                Stride = 2;
                uint16_t Data = 0;
                if (Obj->isLittleEndian()) {
                  const auto *const Short =
                      reinterpret_cast<const support::ulittle16_t *>(
                          Bytes.data() + Index);
                  Data = *Short;
                } else {
                  const auto *const Short =
                      reinterpret_cast<const support::ubig16_t *>(Bytes.data() +
                                                                  Index);
                  Data = *Short;
                }
                InstRaiser->addMCInstOrData(Index, Data);
              } else {
                Stride = 1;
                InstRaiser->addMCInstOrData(Index, Bytes.slice(Index, 1)[0]);
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
        if (Obj->isELF() && Symbols[SI].Type == ELF::STT_OBJECT &&
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
          errs() << format("%8" PRIx64 ":", SectionAddr + Index);
          errs() << "\t";
          dumpBytes(Bytes, errs());
          errs() << CommentStream.str();
          Comments.clear();
          errs() << "\n";
        }

        // Add MCInst to the list if all instructions were decoded
        // successfully till now. Else, do not bother adding since no attempt
        // will be made to raise this function.
        if (Disassembled) {
          InstRaiser->addMCInstOrData(Index, Inst);

          // Find branch target and record it. Call targets are not
          // recorded as they are not needed to build per-function CFG.
          if (MIA && MIA->isBranch(Inst)) {
            uint64_t BranchTarget;
            if (MIA->evaluateBranch(Inst, Index, Size, BranchTarget)) {
              // In a relocatable object, the target's section must reside in
              // the same section as the call instruction, or it is accessed
              // through a relocation.
              //
              // In a non-relocatable object, the target may be in any
              // section.
              //
              // N.B. We don't walk the relocations in the relocatable case
              // yet.
              if (!Obj->isRelocatableObject()) {
                auto SectionAddress = std::upper_bound(
                    SectionAddresses.begin(), SectionAddresses.end(),
                    BranchTarget,
                    [](uint64_t LHS,
                       const std::pair<uint64_t, SectionRef> &RHS) {
                      return LHS < RHS.first;
                    });
                if (SectionAddress != SectionAddresses.begin()) {
                  --SectionAddress;
                }
              }
              // Add the index Target to target indices set.
              BranchTargetSet.insert(BranchTarget);
            }

            // Mark the next instruction as a target, if it is not beyond the
            // function end
            uint64_t FallThruIndex = Index + Size;
            if (FallThruIndex < End) {
              BranchTargetSet.insert(FallThruIndex);
            }
          }
        }
      }
      FFT->eraseFunctionBySymbol(Symbols[SI].Name,
                                 FunctionFilter::FILTER_INCLUDE);
    }
    LLVM_DEBUG(dbgs() << "END Disassembly of Functions in Section : "
                      << SectionName.data() << "\n");

    // Record all targets of the last function parsed
    CurMFRaiser = getCurrentMachineFunctionRaiser();
    for (auto TargetIdx : BranchTargetSet)
      CurMFRaiser->getMCInstRaiser()->addTarget(TargetIdx);

    runMachineFunctionPasses();

    if (!FFT->isFilterSetEmpty(FunctionFilter::FILTER_INCLUDE)) {
      errs() << "***** WARNING: The following include filter symbol(s) are not "
                "found :\n";
      FFT->dump(FunctionFilter::FILTER_INCLUDE);
    }
  }
}
