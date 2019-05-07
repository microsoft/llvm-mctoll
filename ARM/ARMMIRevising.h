//===- ARMMIRevising.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMMIRevising class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMIREVISING_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMIREVISING_H

#include "ARMRaiserBase.h"
#include "llvm/CodeGen/MachineInstr.h"

using namespace llvm;
using namespace object;

/// This class is use to revise information of each MachineInstr. Something
/// like size of operands, immediate data value and so on. Currently, the
/// generation of global objects is included at here.
class ARMMIRevising : public ARMRaiserBase {

public:
  static char ID;

  ARMMIRevising(ARMModuleRaiser &MRsr);
  ~ARMMIRevising() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool revise();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  bool reviseMI(MachineInstr &MI);
  /// Remove some useless operations of instructions.
  bool removeNeedlessInst(MachineInstr *MInst);
  /// Create function for external function.
  uint64_t getCalledFunctionAtPLTOffset(uint64_t PLTEndOff, uint64_t CallAddr);
  /// Relocate call branch instructions in object files.
  void relocateBranch(MachineInstr &MInst);
  /// Address PC relative data in function, and create corresponding global
  /// value.
  void addressPCRelativeData(MachineInstr &MInst);
  /// Decode modified immediate constants in some instructions with immediate
  /// operand.
  void decodeModImmOperand(MachineInstr &MInst);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMIREVISING_H
