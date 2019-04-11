//===-- ARMCreateJumpTable.h - Binary raiser utility llvm-mctoll -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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
#include "MCInstRaiser.h"
#include "MachineFunctionRaiser.h"

class ARMCreateJumpTable : public ARMRaiserBase {
public:
  static char ID;

  ARMCreateJumpTable(ARMModuleRaiser &mr);
  ~ARMCreateJumpTable() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool create();
  bool runOnMachineFunction(MachineFunction &mf) override;
  bool getJTlist(std::vector<JumpTableInfo> &List);

private:
  unsigned int getARMCPSR(unsigned int PhysReg);
  bool raiseMaichineJumpTable(MachineFunction &MF);
  MachineBasicBlock *checkJumptableBB(MachineFunction &MF);
  bool UpdatetheBranchInst(MachineBasicBlock &MBB);
  std::vector<JumpTableInfo> jtList;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMCREATEJUMPTABLE_H
