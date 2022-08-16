//===- FunctionRaisingInfo.cpp - Binary raiser utility llvm-mctoll --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of FunctionRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "FunctionRaisingInfo.h"
#include "llvm/CodeGen/SelectionDAG.h"

using namespace llvm;
using namespace llvm::mctoll;

/// Initialize this FunctionRaisingInfo with the given Function and its
/// associated MachineFunction.
void FunctionRaisingInfo::set(ARMModuleRaiser &mr, Function &fn,
                              MachineFunction &mf, SelectionDAG *dag) {
  MR = &mr;
  Fn = &fn;
  MF = &mf;
  CTX = dag->getContext();
  DLT = &MR->getModule()->getDataLayout();

  DefaultType = Type::getIntNTy(*CTX, DLT->getPointerSizeInBits());
}

SDValue FunctionRaisingInfo::getValueByRegister(unsigned reg) {
  assert((RegValMap.count(reg) != 0) &&
         "Can not find the corresponding value!");
  return SDValue(RegValMap[reg], 0);
}

void FunctionRaisingInfo::setValueByRegister(unsigned reg, SDValue val) {
  assert((val.getNode() != nullptr) && "Can not map a nullptr to a register!");
  RegValMap[reg] = val.getNode();
}

SDValue FunctionRaisingInfo::getValFromRegMap(SDValue val) {
  unsigned reg = static_cast<RegisterSDNode *>(val.getNode())->getReg();
  return (RegValMap.count(reg) == 0) ? val : SDValue(RegValMap[reg], 0);
}

/// Clear out all the function-specific state. This returns this
/// FunctionRaisingInfo to an empty state, ready to be used for a
/// different function.
void FunctionRaisingInfo::clear() {
  MBBMap.clear();
  ValueMap.clear();
  VisitedBBs.clear();
  RegValMap.clear();
  ArgValMap.clear();
  NodeRegMap.clear();
  AllocaMap.clear();
  RetValMap.clear();
}

/// Get the corresponding BasicBlock of given MachineBasicBlock.
BasicBlock *FunctionRaisingInfo::getBasicBlock(MachineBasicBlock &mbb) {
  for (auto bb : MBBMap) {
    if (bb.second == &mbb)
      return const_cast<BasicBlock *>(bb.first);
  }

  return nullptr;
}

/// Get the corresponding BasicBlock of given MachineBasicBlock.
/// If does not give a MachineBasicBlock, it will create a new BasicBlock
/// on current Function, and returns it.
BasicBlock *FunctionRaisingInfo::getOrCreateBasicBlock(MachineBasicBlock *mbb) {
  Function *fn = getCRF();
  if (mbb == nullptr)
    return BasicBlock::Create(fn->getContext(), "", fn);

  BasicBlock *bb = getBasicBlock(*mbb);
  if (bb != nullptr)
    return bb;

  if (&MF->front() == mbb)
    bb = &fn->getEntryBlock();
  else
    bb = BasicBlock::Create(fn->getContext(), "", fn);

  MBBMap.insert(std::make_pair(bb, mbb));

  return bb;
}
