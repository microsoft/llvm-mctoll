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

#include "ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

class ARMRaiserBase : public FunctionPass {
protected:
  ARMRaiserBase() = delete;
  ARMRaiserBase(char &PassID, ModuleRaiser &mr) : FunctionPass(PassID), MR(mr) {
    PrintPass =
        (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() >
         0);
  }
  ~ARMRaiserBase() override {}
  virtual void init(MachineFunction *mf = nullptr, Function *rf = nullptr) {
    if (mf)
      MF = mf;
    if (rf)
      RF = rf;
  }
  virtual bool runOnMachineFunction(MachineFunction &mf) { return false; }
  bool runOnFunction(Function &f) override {
    RF = &f;
    MF = MR.getMachineFunction(&f);
    return runOnMachineFunction(*MF);
  }

  /// Get current raised llvm::Function.
  Function *getCRF() { return RF; }

  bool PrintPass;
  ModuleRaiser &MR;
  /// Current raised llvm::Function.
  Function *RF;
  MachineFunction *MF;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMRAISERBASE_H
