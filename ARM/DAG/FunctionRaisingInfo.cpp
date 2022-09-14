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
void FunctionRaisingInfo::set(ARMModuleRaiser &MRVal, Function &FNVal,
                              MachineFunction &MFVal, SelectionDAG *DAG) {
  MR = &MRVal;
  Fn = &FNVal;
  MF = &MFVal;
  CTX = DAG->getContext();
  DLT = &MR->getModule()->getDataLayout();

  DefaultType = Type::getIntNTy(*CTX, DLT->getPointerSizeInBits());
}

SDValue FunctionRaisingInfo::getValueByRegister(unsigned Reg) {
  assert((RegValMap.count(Reg) != 0) &&
         "Can not find the corresponding value!");
  return SDValue(RegValMap[Reg], 0);
}

void FunctionRaisingInfo::setValueByRegister(unsigned Reg, SDValue Val) {
  assert((Val.getNode() != nullptr) && "Can not map a nullptr to a register!");
  RegValMap[Reg] = Val.getNode();
}

SDValue FunctionRaisingInfo::getValFromRegMap(SDValue Val) {
  Register Reg = static_cast<RegisterSDNode *>(Val.getNode())->getReg();
  return (RegValMap.count(Reg) == 0) ? Val : SDValue(RegValMap[Reg], 0);
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
BasicBlock *FunctionRaisingInfo::getBasicBlock(MachineBasicBlock &MBB) {
  for (auto Block : MBBMap) {
    if (Block.second == &MBB)
      return const_cast<BasicBlock *>(Block.first);
  }

  return nullptr;
}

/// Get the corresponding BasicBlock of given MachineBasicBlock.
/// If does not give a MachineBasicBlock, it will create a new BasicBlock
/// on current Function, and returns it.
BasicBlock *FunctionRaisingInfo::getOrCreateBasicBlock(MachineBasicBlock *MBB) {
  Function *Fn = getCRF();
  if (MBB == nullptr)
    return BasicBlock::Create(Fn->getContext(), "", Fn);

  BasicBlock *Block = getBasicBlock(*MBB);
  if (Block != nullptr)
    return Block;

  if (&MF->front() == MBB)
    Block = &Fn->getEntryBlock();
  else
    Block = BasicBlock::Create(Fn->getContext(), "", Fn);

  MBBMap.insert(std::make_pair(Block, MBB));

  return Block;
}
