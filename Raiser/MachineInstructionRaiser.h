//===-- MachineInstructionRaiser.h ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of MachineInstructionRaiser class used
// by llvm-mctoll. This class encapsulates the raising of MachineInstruction
// to LLVM Instruction
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H

#include "Raiser/MCInstRaiser.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"

namespace llvm {
namespace mctoll {

/// Structure holding all necessary information to raise control
/// transfer (i.e., branch) instructions during a post-processing
/// phase.
struct ControlTransferInfo {
  BasicBlock *CandidateBlock;
  // This is the MachineInstr that needs to be raised
  const MachineInstr *CandidateMachineInstr;
  // A vector of values that could be of use while raising
  // CandidateMachineInstr. If it is a call instruction,
  // this vector has the Values corresponding to argument
  // registers (TODO : need to handles arguments passed on stack)
  // If this is a conditional branch instruction, it contains the
  // EFLAG bit values.
  std::vector<Value *> RegValues;
  // Flag to indicate that CandidateMachineInstr has been raised
  bool Raised;
};

class MachineInstructionRaiser {
public:
  MachineInstructionRaiser() = delete;
  MachineInstructionRaiser(MachineFunction &TheMF, const ModuleRaiser *TheMR,
                           MCInstRaiser *TheMCIR = nullptr)
      : MF(TheMF), RaisedFunction(nullptr), InstRaiser(TheMCIR), MR(TheMR) {}
  virtual ~MachineInstructionRaiser(){};

  virtual bool raise() { return true; };
  virtual FunctionType *getRaisedFunctionPrototype() = 0;
  virtual int getArgumentNumber(unsigned PReg) = 0;
  virtual Value *getRegOrArgValue(unsigned PReg, int MBBNo) = 0;
  virtual bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                                      std::vector<Type *> &) = 0;

  Function *getRaisedFunction() { return RaisedFunction; }
  void setRaisedFunction(Function *RF) { RaisedFunction = RF; }
  MCInstRaiser *getMCInstRaiser() { return InstRaiser; }
  MachineFunction &getMF() { return MF; };
  const ModuleRaiser *getModuleRaiser() { return MR; }

  std::vector<ControlTransferInfo *> getControlTransferInfo() {
    return CTInfo;
  };

  // Helper function added since LLVM deprecated getPointerElementType() API
  // Get type of a pointer or non-pointer typed Val
  static Type *getPointerElementType(const Value *Val) {
    assert(Val && "Attempt to obtain element type of a null type");
    Type *ValTy = Val->getType();
    assert(ValTy->isPointerTy() &&
           "Attempt to obtain element type of a non-pointer type");

    Type *RetTy = nullptr;
    if (isa<AllocaInst>(Val)) {
      RetTy = dyn_cast<AllocaInst>(Val)->getAllocatedType();
    } else if (isa<GlobalVariable>(Val)) {
      RetTy = dyn_cast<GlobalVariable>(Val)->getValueType();
    } else if (isa<GetElementPtrInst>(Val)) {
      RetTy = dyn_cast<GetElementPtrInst>(Val)->getSourceElementType();
    } else if (isa<GEPOperator>(Val)) {
      RetTy = dyn_cast<GEPOperator>(Val)->getResultElementType();
    } else if (isa<LoadInst>(Val)) {
      RetTy = dyn_cast<LoadInst>(Val)->getType();
    } else if (isa<StoreInst>(Val)) {
      RetTy = dyn_cast<StoreInst>(Val)->getValueOperand()->getType();
    } else if (isa<CallInst>(Val)) {
      RetTy = dyn_cast<CallInst>(Val)->getFunctionType();
    } else if (isa<IntToPtrInst>(Val)) {
      RetTy = dyn_cast<IntToPtrInst>(Val)->getSrcTy();
    } else {
      assert(false && "Unhandled pointer type");
    }
    return RetTy;
  };

protected:
  MachineFunction &MF;
  // This is the Function object that holds the raised abstraction of MF.
  // Note that the function associated with MF should not be referenced or
  // updated. It was created just to enable the creation of MF.
  Function *RaisedFunction;
  MCInstRaiser *InstRaiser;
  const ModuleRaiser *MR;

  // A vector of information to be used for raising of control transfer
  // (i.e., Call and Terminator) instructions.
  std::vector<ControlTransferInfo *> CTInfo;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H
