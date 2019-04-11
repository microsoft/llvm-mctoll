//===- ARMInstructionSplitting.h --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMInstructionSplitting class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMINSTRUCTIONSPLITTING_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMINSTRUCTIONSPLITTING_H

#include "ARMBaseInstrInfo.h"
#include "ARMRaiserBase.h"
#include "ARMSubtarget.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

using namespace llvm;

/// ARMInstructionSplitting - Some instructions which their patterns include
/// more than one operations, like 'add r0, r1, r0, asr r1' or
/// 'ldr r0, [r1, #4]', are splitted into multiple MIs at here.
class ARMInstructionSplitting : public ARMRaiserBase {
public:
  static char ID;
  ARMInstructionSplitting(ARMModuleRaiser &mr);
  ~ARMInstructionSplitting() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool split();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  /// checkisShifter - Check if the MI has shift pattern.
  unsigned checkisShifter(unsigned Opcode);
  /// getShiftOpcode - Get the shift opcode in MI.
  unsigned getShiftOpcode(ARM_AM::ShiftOpc SOpc, unsigned OffSet);
  MachineInstr *splitLDRSTR(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRPre(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRPreImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitCommon(MachineBasicBlock &MBB, MachineInstr &MI,
                            unsigned newOpc);
  MachineInstr *splitS(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned newOpc, int idx);
  MachineInstr *splitC(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned newOpc, int idx);
  MachineInstr *splitCS(MachineBasicBlock &MBB, MachineInstr &MI,
                        unsigned newOpc, int idx);
  /// isShift_C - True if the ARM instruction performs Shift_C().
  bool isShift_C(unsigned Opcode);
  /// getLoadStoreOpcode - No matter what pattern of Load/Store is, change
  /// the Opcode to xxxi12.
  unsigned getLoadStoreOpcode(unsigned Opcode);
  /// isLDRSTRPre - If the MI is load/store which needs wback,
  /// it will return true;
  bool isLDRSTRPre(unsigned Opcode);
  MachineInstrBuilder &addOperand(MachineInstrBuilder &mib, MachineOperand &mo,
                                  bool isDef = false);

  MachineRegisterInfo *MRI;
  const ARMBaseInstrInfo *TII;
  LLVMContext *CTX;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMINSTRUCTIONSPLITTING_H
