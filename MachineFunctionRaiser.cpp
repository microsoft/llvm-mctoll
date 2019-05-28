//===-- MachineFunctionRaiser.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MachineFunctionRaiser.h"
#include "llvm/Target/TargetMachine.h"

void MachineFunctionRaiser::init(uint64_t start, uint64_t end) {
  mcInstRaiser = new MCInstRaiser(start, end);
  machineInstRaiser = nullptr;
}

bool MachineFunctionRaiser::runRaiserPasses() {
  bool success = false;
  // Raise MCInst to MachineInstr and Build CFG
  if (machineInstRaiser != nullptr) {
    // Raise MachineInstr to Instruction
    success = machineInstRaiser->raise();
  }
  cleanupRaisedFunction();
  return success;
}

// Cleanup empty basic blocks from raised function
void MachineFunctionRaiser::cleanupRaisedFunction() {
  Function *RaisedFunc = getRaisedFunction();
  std::vector<BasicBlock *> EmptyBlocks;
  for (BasicBlock &BB : *RaisedFunc) {
    if (BB.empty()) {
      EmptyBlocks.push_back(&BB);
    }
  }
  for (BasicBlock *BB : EmptyBlocks) {
    BB->removeFromParent();
  }
  return;
}

/* NOTE : The following ModuleRaiser class functions are defined here as they
 * reference MachineFunctionRaiser class that has a forward declaration in
 * ModuleRaiser.h.
 */

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

#ifdef __cplusplus
extern "C" {
#endif

#define MODULE_RAISER(TargetName) void Initialize##TargetName##ModuleRaiser();
#include "Raisers.def"
#ifdef __cplusplus
}
#endif

void ModuleRaiser::InitializeAllModuleRaisers() {
#define MODULE_RAISER(TargetName) Initialize##TargetName##ModuleRaiser();
#include "Raisers.def"
}
