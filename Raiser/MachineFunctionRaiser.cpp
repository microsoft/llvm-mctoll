//===-- MachineFunctionRaiser.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MachineFunctionRaiser.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm::mctoll;

bool MachineFunctionRaiser::runRaiserPasses() {
  bool Success = false;
  // Raise MCInst to MachineInstr and Build CFG
  if (MachineInstRaiser != nullptr)
    Success = MachineInstRaiser->raise();

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

MachineInstructionRaiser *MachineFunctionRaiser::getMachineInstrRaiser() {
  return MachineInstRaiser;
}

Function *MachineFunctionRaiser::getRaisedFunction() {
  return MachineInstRaiser->getRaisedFunction();
}

void MachineFunctionRaiser::setRaisedFunction(Function *F) {
  return MachineInstRaiser->setRaisedFunction(F);
}
