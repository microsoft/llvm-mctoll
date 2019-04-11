//===- ARMArgumentRaiser.h --------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMArgumentRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H

#include "ARMRaiserBase.h"

using namespace llvm;

/// ARMArgumentRaiser - Each function argument is remarked as stack slot at
/// here, it is used to identify the function arguments in emitting DAG. Using
/// stack 0 represent the return value, and using stack index from 1 to argument
/// count to represent function arguments of MachineInstr.
class ARMArgumentRaiser : public ARMRaiserBase {

public:
  static char ID;

  ARMArgumentRaiser(ARMModuleRaiser &mr);
  ~ARMArgumentRaiser() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool raiseArgs();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  int genStackObject(int idx);
  /// updateReturnRegister - Change all return relative register operands to
  /// stack 0.
  void updateReturnRegister(MachineFunction &mf);
  /// updateParameterRegister - Change all function arguments of registers into
  /// stack elements with same indexes of arguments.
  void updateParameterRegister(unsigned reg, MachineBasicBlock &mbb);
  /// updateParameterFrame - Change rest of function arguments on stack frame
  /// into stack elements.
  void updateParameterFrame(MachineFunction &mf);
  /// updateParameterInstr - Using newly created stack elements replace relative
  /// operands in MachineInstr.
  void updateParameterInstr(MachineFunction &mf);

  MachineFrameInfo *MFI;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H
