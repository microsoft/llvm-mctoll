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
#include "llvm/IR/Instructions.h"

Function *ModuleRaiser::getRaisedFunctionAt(uint64_t Index) const {
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
  for (auto MIR : mfRaiserVector) {
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
            if (auto RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
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
