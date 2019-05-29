//===-- ARMEliminatePrologEpilog.h ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMEliminatePrologEpilog class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMELIMINATEPROLOGEPILOG_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMELIMINATEPROLOGEPILOG_H

#include "ARMRaiserBase.h"

using namespace llvm;

class ARMEliminatePrologEpilog : public ARMRaiserBase {
public:
  static char ID;

  ARMEliminatePrologEpilog(ARMModuleRaiser &mr);
  ~ARMEliminatePrologEpilog();
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool eliminate();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  bool checkRegister(unsigned Reg, std::vector<MachineInstr *> &instrs) const;
  bool eliminateProlog(MachineFunction &mf) const;
  bool eliminateEpilog(MachineFunction &mf) const;
  /// Analyze stack size base on moving sp.
  void analyzeStackSize(MachineFunction &mf);
  /// Analyze frame adjustment base on the offset between fp and base sp.
  void analyzeFrameAdjustment(MachineFunction &mf);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMELIMINATEPROLOGEPILOG_H
