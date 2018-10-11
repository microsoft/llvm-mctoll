//===-- MachineFunctionRaiser.cpp - Binary raiser utility llvm-mctoll -----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementaion of MachineFunctionRaiser class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "MachineFunctionRaiser.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Target/TargetMachine.h"

#ifdef __cplusplus
extern "C" {
#endif

// ARM Raiser passes
MachineInstructionRaiser *
InitializeARMMachineInstructionRaiser(MachineFunction &machFunc, Module &m,
                                      const ModuleRaiser *mr,
                                      MCInstRaiser *mcir);

// X86 Raiser passes
MachineInstructionRaiser *
InitializeX86MachineInstructionRaiser(MachineFunction &machFunc, Module &m,
                                      const ModuleRaiser *mr,
                                      MCInstRaiser *mcir);
#ifdef __cplusplus
}
#endif

void MachineFunctionRaiser::init(uint64_t start, uint64_t end) {
  mcInstRaiser = new MCInstRaiser(start, end);
  machineInstRaiser = nullptr;
  auto arch = MR->getTargetMachine()->getTargetTriple().getArch();

  // Double check supported architecture.
  if (!MR->isSupportedArch()) {
    outs() << arch << "Unsupported architecture\n";
    return;
  }

  switch (arch) {
  case Triple::x86_64:
    machineInstRaiser =
        InitializeX86MachineInstructionRaiser(MF, module, MR, mcInstRaiser);
    break;
  case Triple::arm:
    machineInstRaiser =
        InitializeARMMachineInstructionRaiser(MF, module, MR, mcInstRaiser);
    break;
  // Add default case to pacify the compiler warnings.
  default:
    outs() << "\n" << arch << " not yet supported for raising\n";
  }
}

bool MachineFunctionRaiser::runRaiserPasses() {
  bool success = false;
  // Do not run raise binaries of an unsupported architecture.
  if (!MR->isSupportedArch())
    return false;

  // Raise MCInst to MachineInstr and Build CFG
  if (machineInstRaiser != nullptr) {
    // Raise MachineInstr to Instruction
    success = machineInstRaiser->raise();
  }
  return success;
}

/* NOTE : The following ModuleRaiser class functions are defined here as they
 * reference MachineFunctionRaiser class that has a forward declaration in
 * ModuleRaiser.h.
 */
// Create a new MachineFunctionRaiser object and add it to the list of
// MachineFunction raiser objects of this module.
MachineFunctionRaiser *ModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *f, const ModuleRaiser *mr, uint64_t start, uint64_t end) {
  MachineFunctionRaiser *mfRaiser = new MachineFunctionRaiser(
      M, mr->getMachineModuleInfo()->getOrCreateMachineFunction(*f), mr, start,
      end);
  mfRaiserVector.push_back(mfRaiser);
  return mfRaiser;
}

Function *ModuleRaiser::getFunctionAt(uint64_t Index) const {
  int64_t TextSecAddr = getTextSectionAddress();
  for (auto MFR : mfRaiserVector) {
    if ((MFR->getMCInstRaiser()->getFuncStart() + TextSecAddr) == Index) {
      return MFR->getRaisedFunction();
    }
  }
  return nullptr;
}

const RelocationRef *ModuleRaiser::getDynRelocAtOffset(uint64_t Loc) const {
  if (DynRelocs.empty()) {
    return nullptr;
  }
  auto relocIter = std::find_if(
      DynRelocs.begin(), DynRelocs.end(),
      [Loc](const RelocationRef &a) -> bool { return (a.getOffset() == Loc); });
  if (relocIter != DynRelocs.end()) {
    return &(*relocIter);
  } else {
    return nullptr;
  }
}

// Return relocation whose offset is in the range [Index, Index+Size)
const RelocationRef *ModuleRaiser::getTextRelocAtOffset(uint64_t Index,
                                                        uint64_t Size) const {
  if (TextRelocs.empty()) {
    return nullptr;
  }
  auto relocIter = std::find_if(TextRelocs.begin(), TextRelocs.end(),
                                [Index, Size](const RelocationRef &a) -> bool {
                                  return ((a.getOffset() >= Index) &&
                                          (a.getOffset() < (Index + Size)));
                                });
  if (relocIter != TextRelocs.end()) {
    return &(*relocIter);
  } else {
    return nullptr;
  }
}

Function *ModuleRaiser::getCalledFunctionUsingTextReloc(uint64_t Loc,
                                                        uint64_t Size) const {
  // Find the text relocation with offset in the range [Loc, Loc+Size)
  const RelocationRef *textReloc = getTextRelocAtOffset(Loc, Loc + Size);
  if (textReloc != nullptr) {
    Expected<StringRef> sym = textReloc->getSymbol()->getName();
    assert(sym && "Failed to find call target symbol");
    for (auto MFR : mfRaiserVector) {
      Function *FP = MFR->getRaisedFunction();
      assert(FP && "Unexpected null function pointer encountered");
      if (sym->equals(FP->getName()))
        return FP;
    }
  }
  return nullptr;
}

bool ModuleRaiser::runMachineFunctionPasses() {
  bool success = true;

  // For each of the functions, run passes to
  // set up for instruction raising.
  for (auto MFR : mfRaiserVector) {
    // 1. Build CFG
    MCInstRaiser *MCIR = MFR->getMCInstRaiser();
    // Populates the MachineFunction with CFG.
    MCIR->buildCFG(MFR->getMachineFunction(), MIA, MII);

    // 2. Construct function prototype.
    // Knowing the function prototypes prior to raising the instructions
    // facilitates raising of call instructions whose targets are within
    // the current module.
    // TODO : Adjust this when raising multiple modules.
    Function *RF = MFR->getRaisedFunction();
    if (RF == nullptr) {
      FunctionType *FT =
          MFR->getMachineInstrRaiser()->getRaisedFunctionPrototype();
      assert(FT != nullptr && "Failed to build function prototype");
    }
  }
  // Run instruction raiser passes.
  for (auto MFR : mfRaiserVector) {
    success |= MFR->runRaiserPasses();
  }
  return success;
}

// Get the MachineFunction associated with the placeholder
// function corresponding to raised function.
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
    section_iterator RelocatedSecIter = CandRelocSection.getRelocatedSection();
    // If the CandRelocSection has a corresponding relocated section
    if (RelocatedSecIter != Obj->section_end()) {
      // If the corresponding relocated section is TextSec, CandRelocSection
      // is the section with relocation information for TextSec.
      if (RelocatedSecIter->getIndex() == (uint64_t)TextSectionIndex) {
        for (const RelocationRef &reloc : CandRelocSection.relocations()) {
          TextRelocs.push_back(reloc);
        }
        // Sort the relocations
        std::sort(TextRelocs.begin(), TextRelocs.end(),
                  [](const RelocationRef &a, const RelocationRef &b) -> bool {
                    return a.getOffset() < b.getOffset();
                  });
        break;
      }
    }
  }
  return true;
}

bool ModuleRaiser::collectDynamicRelocations() {

  if (!Obj->isELF()) {
    return false;
  }

  const ELF64LEObjectFile *Elf64LEObjFile = dyn_cast<ELF64LEObjectFile>(Obj);
  if (!Elf64LEObjFile) {
    return false;
  }

  std::vector<SectionRef> DynRelSec = Obj->dynamic_relocation_sections();

  for (const SectionRef &Section : DynRelSec) {
    for (const RelocationRef &Reloc : Section.relocations()) {
      DynRelocs.push_back(Reloc);
    }
  }

  // Get relocations of .got.plt section from .rela.plt if it exists. I do not
  // see an API in ObjectFile class to get at these.

  // Find .got.plt and .rela.plt sections Note: A lot of verification and double
  // checking done in the following code.
  const ELFFile<ELF64LE> *ElfFile = Elf64LEObjFile->getELFFile();
  // Find .rela.plt
  SectionRef DotGotDotPltSec, DotRelaDotPltSec;
  for (const SectionRef Section : Obj->sections()) {
    StringRef SecName;
    Section.getName(SecName);
    if (SecName.equals(".rela.plt")) {
      DotRelaDotPltSec = Section;
    } else if (SecName.equals(".got.plt")) {
      DotGotDotPltSec = Section;
    }
  }
  if (DotRelaDotPltSec.getObject() != nullptr) {
    // Do some additional sanity checks
    assert((DotGotDotPltSec.getObject() != nullptr) &&
           "Failed to find .got.plt section");
    auto DotRelaDotPltShdr = ElfFile->getSection(DotRelaDotPltSec.getIndex());
    assert(DotRelaDotPltShdr && "Failed to find .rela.plt section");
    assert((DotRelaDotPltShdr.get()->sh_info == DotGotDotPltSec.getIndex()) &&
           ".rela.plt does not refer .got.plt section");
    assert((DotRelaDotPltShdr.get()->sh_type == ELF::SHT_RELA) &&
           "Unexpected type of section .rela.plt");
    for (const RelocationRef &Reloc : DotRelaDotPltSec.relocations()) {
      DynRelocs.push_back(Reloc);
    }
  }
  return true;
}

// Return text section address; or -1 if text section is not found
int64_t ModuleRaiser::getTextSectionAddress() const {
  if (!Obj->isELF()) {
    return -1;
  }
  assert(TextSectionIndex >= 0 && "Unexpected negative index of text section");
  for (SectionRef Sec : Obj->sections()) {
    if (Sec.getIndex() == (unsigned)TextSectionIndex) {
      return Sec.getAddress();
    }
  }
  assert(false && "Failed to locate text section.");
  return -1;
}

const Value *ModuleRaiser::getRODataValueAt(uint64_t offset) const {
  Value *V = nullptr;
  auto iter = GlobalRODataValues.find(offset);
  if (iter != GlobalRODataValues.end()) {
    V = iter->second;
  }
  return V;
}

void ModuleRaiser::addRODataValueAt(Value *v, uint64_t offset) const {
  assert((GlobalRODataValues.find(offset) == GlobalRODataValues.end()) &&
         "Attempt to insert value for already existing rodata location");
  GlobalRODataValues.emplace(offset, v);
  return;
}
