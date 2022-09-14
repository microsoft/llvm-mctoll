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

namespace llvm {
namespace mctoll {

class ARMEliminatePrologEpilog : public ARMRaiserBase {
public:
  static char ID;

  ARMEliminatePrologEpilog(ARMModuleRaiser &MR, MachineFunction *MF, Function *RF);
  ~ARMEliminatePrologEpilog();

  bool eliminate();
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  bool checkRegister(unsigned Reg, std::vector<MachineInstr *> &Instrs) const;
  bool eliminateProlog(MachineFunction &MF) const;
  bool eliminateEpilog(MachineFunction &MF) const;
  /// Analyze stack size base on moving sp.
  void analyzeStackSize(MachineFunction &MF);
  /// Analyze frame adjustment base on the offset between fp and base sp.
  void analyzeFrameAdjustment(MachineFunction &MF);
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMELIMINATEPROLOGEPILOG_H
