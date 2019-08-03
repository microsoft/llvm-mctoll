//===-- MachineFunctionRaiser.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MachineFunctionRaiser.h"
#include "llvm/Target/TargetMachine.h"

bool MachineFunctionRaiser::runRaiserPasses() {
  bool Success = false;
  // Raise MCInst to MachineInstr and Build CFG
  if (machineInstRaiser != nullptr)
    Success = machineInstRaiser->raise();

  cleanupRaisedFunction();
  return Success;
}

// Cleanup empty basic blocks from raised function
void MachineFunctionRaiser::cleanupRaisedFunction() {
  Function *RaisedFunc = getRaisedFunction();
  std::vector<BasicBlock *> EmptyBlocks;
  for (BasicBlock &BB : *RaisedFunc)
    if (BB.empty())
      EmptyBlocks.push_back(&BB);

  for (BasicBlock *BB : EmptyBlocks)
    BB->removeFromParent();
}

// NOTE : The following ModuleRaiser class functions are defined here as they
// reference MachineFunctionRaiser class that has a forward declaration in
// ModuleRaiser.h.

Function *ModuleRaiser::getFunctionAt(uint64_t Index) const {
  int64_t TextSecAddr = getTextSectionAddress();
  for (auto MFR : mfRaiserVector)
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
    for (auto MFR : mfRaiserVector) {
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

  // For each of the functions, run passes to set up for instruction raising.
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
  for (auto MFR : mfRaiserVector)
    Success |= MFR->runRaiserPasses();

  return Success;
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
        for (const RelocationRef &reloc : CandRelocSection.relocations())
          TextRelocs.push_back(reloc);

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
  if (!Obj->isELF())
    return -1;

  assert(TextSectionIndex >= 0 && "Unexpected negative index of text section");
  for (SectionRef Sec : Obj->sections())
    if (Sec.getIndex() == (unsigned)TextSectionIndex)
      return Sec.getAddress();

  llvm_unreachable("Failed to locate text section.");
}

const Value *ModuleRaiser::getRODataValueAt(uint64_t Offset) const {
  auto Iter = GlobalRODataValues.find(Offset);
  if (Iter != GlobalRODataValues.end())
    return Iter->second;

  return nullptr;
}

void ModuleRaiser::addRODataValueAt(Value *V, uint64_t Offset) const {
  assert((GlobalRODataValues.find(Offset) == GlobalRODataValues.end()) &&
         "Attempt to insert value for already existing rodata location");
  GlobalRODataValues.emplace(Offset, V);
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
