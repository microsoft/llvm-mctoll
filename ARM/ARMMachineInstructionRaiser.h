//===-- ARMMachineInstructionRaiser.h - Binary raiser utility llvm-mctoll -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMMachineInstructionRaiser class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H

#include "MachineInstructionRaiser.h"

class ARMMachineInstructionRaiser : public MachineInstructionRaiser {
public:
  ARMMachineInstructionRaiser() = delete;
  ARMMachineInstructionRaiser(MachineFunction &machFunc, const ModuleRaiser *mr,
                              MCInstRaiser *mcir);
  bool raise();
  FunctionType *getRaisedFunctionPrototype();
  int getArgumentNumber(unsigned PReg);
  Value *getRegOrArgValue(unsigned PReg, int MBBNo);
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &);

  std::vector<JumpTableInfo> jtList;

private:
  bool raiseMachineFunction();
  // Commonly used LLVM data structures during this phase
  MachineRegisterInfo &machRegInfo;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
