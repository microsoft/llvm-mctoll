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

MachineInstructionRaiser *MachineFunctionRaiser::getMachineInstrRaiser() {
  return machineInstRaiser;
}

Function *MachineFunctionRaiser::getRaisedFunction() {
  return machineInstRaiser->getRaisedFunction();
}

void MachineFunctionRaiser::setRaisedFunction(Function *F) {
  return machineInstRaiser->setRaisedFunction(F);
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
