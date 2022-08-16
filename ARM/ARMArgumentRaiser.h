//===- ARMArgumentRaiser.h --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMArgumentRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H

#include "ARMBaseInstrInfo.h"
#include "ARMRaiserBase.h"

namespace llvm {
namespace mctoll {

/// Each function argument is remarked as stack slot at here, it is used to
/// identify the function arguments in emitting DAG. Using stack 0 represent
/// the return value, and using stack index from 1 to argument count to
/// represent function arguments of MachineInstr.
class ARMArgumentRaiser : public ARMRaiserBase {

public:
  static char ID;

  ARMArgumentRaiser(ARMModuleRaiser &mr);
  ~ARMArgumentRaiser() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool raiseArgs();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  /// Change all return relative register operands to stack 0.
  void updateReturnRegister(MachineFunction &mf);
  /// Change all function arguments of registers into stack elements with
  /// same indexes of arguments.
  void updateParameterRegister(unsigned reg, MachineBasicBlock &mbb);
  /// Change rest of function arguments on stack frame into stack elements.
  void updateParameterFrame(MachineFunction &mf);
  /// Using newly created stack elements replace relative operands in
  /// MachineInstr.
  void updateParameterInstr(MachineFunction &mf);
  /// Move arguments which are passed by ARM registers(R0 - R3) from function
  /// arg.x to corresponding registers in entry block.
  void moveArgumentToRegister(unsigned Reg, MachineBasicBlock &PMBB);

  MachineFrameInfo *MFI;
  const ARMBaseInstrInfo *TII;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMARGUMENTRAISER_H
