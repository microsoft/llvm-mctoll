//===- ARMCreateJumpTable.h - Binary raiser utility llvm-mctoll -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMCreateJumpTable
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMCREATEJUMPTABLE_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMCREATEJUMPTABLE_H

#include "ARMRaiserBase.h"
#include "Raiser/MCInstRaiser.h"
#include "Raiser/MachineFunctionRaiser.h"

namespace llvm {
namespace mctoll {

class ARMCreateJumpTable : public ARMRaiserBase {
public:
  static char ID;

  ARMCreateJumpTable(ARMModuleRaiser &mr);
  ~ARMCreateJumpTable() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool create();
  bool runOnMachineFunction(MachineFunction &mf) override;
  bool getJTlist(std::vector<JumpTableInfo> &List);
  void setMCInstRaiser(MCInstRaiser *PMCIR);

private:
  unsigned int getARMCPSR(unsigned int PhysReg);
  bool raiseMaichineJumpTable(MachineFunction &MF);
  /// Get the MachineBasicBlock to add the jumptable instruction.
  MachineBasicBlock *checkJumptableBB(MachineFunction &MF);
  bool UpdatetheBranchInst(MachineBasicBlock &MBB);

  std::vector<JumpTableInfo> jtList;
  MCInstRaiser *MCIR;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMCREATEJUMPTABLE_H
