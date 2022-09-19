//===- FunctionRaisingInfo.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of FunctionRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_FUNCTIONRAISERINGINFO_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_FUNCTIONRAISERINGINFO_H

#include "ARMModuleRaiser.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/CodeGen/FunctionLoweringInfo.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"

namespace llvm {
namespace mctoll {

/// This contains information that is global to a function that is used when
/// raising a region of the function.
class FunctionRaisingInfo : public FunctionLoweringInfo {
public:
  ARMModuleRaiser *MR;
  /// The mapped return Value;
  SDValue RetValue;
  /// The map of physical register with related IR Value. It is used to convert
  /// physical registers to SSA form IR Values.
  DenseMap<unsigned, SDNode *> RegValMap;
  /// Set the Val for Register mapping.
  DenseMap<unsigned, Value *> ArgValMap;
  /// Set register for SDNode mapping.
  DenseMap<SDNode *, unsigned> NodeRegMap;
  /// NZCV mapping.
  DenseMap<unsigned, Value *> AllocaMap;
  /// Function return IR value mapping with its parent BasicBlock, it is used
  /// to create exit BasicBlock.
  DenseMap<BasicBlock *, Value *> RetValMap;

  /// Record the latest value of ARM::R0, if the current function has return
  /// value.
  void setRetValue(SDValue RetVal) { RetValue = RetVal; }
  SDValue getValueByRegister(unsigned Reg);
  void setValueByRegister(unsigned Reg, SDValue Val);
  SDValue getValFromRegMap(SDValue Val);
  /// Initialize this FunctionRaisingInfo with the given Function and its
  /// associated MachineFunction.
  void set(ARMModuleRaiser &MRVal, Function &FNVal, MachineFunction &MFVal,
           SelectionDAG *DAGVal);
  /// Clear out all the function-specific state. This returns this
  /// FunctionRasisingInfo to an empty state, ready to be used for a
  /// different function.
  void clear();
  /// Get current raised llvm::Function.
  Function *getCRF() { return const_cast<Function *>(Fn); }
  /// Get the corresponding BasicBlock of given
  /// MachineBasicBlock.
  BasicBlock *getBasicBlock(MachineBasicBlock &MBB);
  /// Get the corresponding BasicBlock of given MachineBasicBlock. If does not
  /// give a MachineBasicBlock, it will create a new BasicBlock on current
  /// Function, and returns it.
  BasicBlock *getOrCreateBasicBlock(MachineBasicBlock *MBB = nullptr);
  /// Check the stack slot index is represented return element or not.
  bool isReturnIndex(int FrameIndex) { return FrameIndex == 0; }
  /// Check the stack slot index is represented argument or not.
  bool isArgumentIndex(int FrameIndex) {
    assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
    return FrameIndex > 0 && (unsigned)FrameIndex <= Fn->arg_size();
  }
  /// Check the index is stack slot index or not.
  bool isStackIndex(int FrameIndex) {
    assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
    return (unsigned)FrameIndex > Fn->arg_size();
  }

  Type *getDefaultType() { return DefaultType; }
  EVT getDefaultEVT() { return EVT::getEVT(DefaultType); }

  LLVMContext *CTX;
  const DataLayout *DLT;
  Type *DefaultType;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_FUNCTIONRAISERINGINFO_H
