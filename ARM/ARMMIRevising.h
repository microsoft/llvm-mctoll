//===- ARMMIRevising.h ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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

/// ARMMIRevising - This class is use to revise information of each
/// MachineInstr. Something like size of operands, immediate data value and
/// so on. Currently, the generation of global objects is included at here.
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
  /// removeNeedlessInst - Remove some useless operations of instructions.
  bool removeNeedlessInst(MachineInstr *MInst);
  /// getCalledFunctionAtPLTOffset - Create function for external function.
  uint64_t getCalledFunctionAtPLTOffset(uint64_t PLTEndOff, uint64_t CallAddr);
  /// relocateBL - Relocate call branch instructions in object files.
  void relocateBL(MachineInstr &MInst);
  /// addressPCRelativeData - Address PC relative data in function, and create
  /// corresponding global value.
  void addressPCRelativeData(MachineInstr &MInst);
  /// decodeModImmOperand - Decode modified immediate constants in some
  /// instructions with immediate operand.
  void decodeModImmOperand(MachineInstr &MInst);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMIREVISING_H
