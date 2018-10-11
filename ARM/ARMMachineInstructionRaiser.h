//===-- ARMMachineInstructionRaiser.h - Binary raiser utility llvm-mctoll -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMMachineInstructionRaiser
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H

#include "MachineInstructionRaiser.h"

class ARMMachineInstructionRaiser : public MachineInstructionRaiser {
public:
  ARMMachineInstructionRaiser() = delete;
  ARMMachineInstructionRaiser(MachineFunction &machFunc, Module &m,
                              const ModuleRaiser *mr, MCInstRaiser *mcir);
  bool raise();
  FunctionType *getRaisedFunctionPrototype();
  int getArgumentNumber(unsigned int);
  Value *getRegValue(unsigned);
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &);

private:
  bool raiseMachineFunction();
  // Commonly used LLVM data structures during this phase
  MachineRegisterInfo &machRegInfo;

  Module &M;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
