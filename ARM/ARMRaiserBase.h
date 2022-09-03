//===-- ARMRaiserBase.h -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the ARMRaiserBase class. This class
// is a base class that provides some basic utilities to ARM raisers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMRAISERBASE_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMRAISERBASE_H

#include "ARMModuleRaiser.h"
#include "llvm-mctoll.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"

namespace llvm {
namespace mctoll {

class ARMRaiserBase : public FunctionPass {
protected:
  ARMRaiserBase() = delete;
  ARMRaiserBase(char &PassID, ARMModuleRaiser &ArmMR)
      : FunctionPass(PassID), MR(&ArmMR) {
    M = MR->getModule();
  }
  ~ARMRaiserBase() override {}

  virtual void init(MachineFunction *NewMF = nullptr, Function *NewRF = nullptr) {
    if (NewMF)
      MF = NewMF;
    if (NewRF)
      RF = NewRF;
  }

  virtual bool runOnMachineFunction(MachineFunction &CurrMF) { return false; }

  bool runOnFunction(Function &Func) override {
    RF = &Func;
    MF = MR->getMachineFunction(&Func);
    return runOnMachineFunction(*MF);
  }

  /// Get current raised llvm::Function.
  Function *getCRF() { return RF; }

  ARMModuleRaiser *MR;
  /// Current raised llvm::Function.
  Function *RF;
  MachineFunction *MF;
  Module *M;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMRAISERBASE_H
