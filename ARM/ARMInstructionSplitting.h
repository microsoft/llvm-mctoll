//===- ARMInstructionSplitting.h --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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

namespace llvm {
namespace mctoll {

/// Some instructions which their patterns include more than one operations,
/// like 'add r0, r1, r0, asr r1' or 'ldr r0, [r1, #4]', are splitted into
/// multiple MIs at here.
class ARMInstructionSplitting : public ARMRaiserBase {
public:
  static char ID;
  ARMInstructionSplitting(ARMModuleRaiser &MR, MachineFunction *MF, Function *RF);
  ~ARMInstructionSplitting() override;

  bool split();
  bool runOnMachineFunction(MachineFunction &mf) override;

private:
  /// Check if the MI has shift pattern.
  unsigned checkisShifter(unsigned Opcode);
  /// Get the shift opcode in MI.
  unsigned getShiftOpcode(ARM_AM::ShiftOpc SOpc, unsigned OffSet);
	/// Split LDRxxx/STRxxx<c><q> <Rd>, [<Rn>, +/-<Rm>{, <shift>}] to:
	/// Rm shift #imm, but write result to VReg.
	/// Add VReg, Rn, Rm
	/// LDRxxx/STRxxx Rd, [VReg]
	MachineInstr* splitLDRSTR(MachineBasicBlock &MBB, MachineInstr &MI) {
		unsigned Simm = MI.getOperand(3).getImm();
		unsigned SOffSet = ARM_AM::getAM2Offset(Simm);
		ARM_AM::ShiftOpc SOpc = ARM_AM::getAM2ShiftOpc(Simm);
		Register SVReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);
		Register AVReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);
		MachineOperand &Rd = MI.getOperand(0);
		MachineOperand &Rn = MI.getOperand(1);
		MachineOperand &Rm = MI.getOperand(2);
		unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
		// Get Metadata for the fisrt insturction.
		ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
				ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
		MDNode *MDNFir = MDNode::get(*CTX, CMDFir);
		// Get Metadata for the second insturction.
		ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
				ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
		MDNode *MDNSec = MDNode::get(*CTX, CMDSec);
		// Get Metadata for the third insturction.
		ConstantAsMetadata *CMD_thd = ConstantAsMetadata::get(
				ConstantInt::get(*CTX, llvm::APInt(64, 2, false)));
		MDNode *N_thd = MDNode::get(*CTX, CMD_thd);
		unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
		int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
		if (SOffSet > 0) {
			// Split LDRxxx/STRxxx Rd, [Rn, Rm, shift]
			MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(ShiftOpc), SVReg);
			addOperand(Fst, Rm);
			Fst.addImm(SOffSet);
			MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(ARM::ADDrr), AVReg);
			addOperand(Sec, Rn);
			Sec.addReg(SVReg);
			MachineInstrBuilder Thd = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(NewOpc));
			if (MI.mayStore())
				addOperand(Thd, Rd);
			else
				addOperand(Thd, Rd, true);

			Thd.addReg(AVReg);
			// Add CPSR if the MI has.
			if (Idx != -1) {
				Fst.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Fst, MI.getOperand(Idx));
				Sec.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Sec, MI.getOperand(Idx));
				Thd.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Thd, MI.getOperand(Idx));
			}
			Fst.addMetadata(MDNFir);
			Sec.addMetadata(MDNSec);
			Thd.addMetadata(N_thd);
		} else if (ShiftOpc == ARM::RRX) {
			// Split LDRxxx/STRxxx Rd, [Rn, Rm, rrx]
			MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(ShiftOpc), SVReg);
			addOperand(Fst, Rm);
			MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(ARM::ADDrr), AVReg);
			addOperand(Sec, Rn);
			Sec.addReg(SVReg);
			MachineInstrBuilder Thd = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(NewOpc));
			if (MI.mayStore())
				addOperand(Thd, Rd);
			else
				addOperand(Thd, Rd, true);

			Thd.addReg(AVReg);
			// Add CPSR if the MI has.
			if (Idx != -1) {
				Sec.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Sec, MI.getOperand(Idx));
				Thd.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Thd, MI.getOperand(Idx));
			}
			Fst.addMetadata(MDNFir);
			Sec.addMetadata(MDNSec);
			Thd.addMetadata(N_thd);
		} else {
			// Split LDRxxx/STRxxx Rd, [Rn, Rm]
			MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(ARM::ADDrr), AVReg);
			addOperand(Fst, Rn);
			addOperand(Fst, Rm);
			MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
					TII->get(NewOpc));
			if (MI.mayStore())
				addOperand(Sec, Rd);
			else
				addOperand(Sec, Rd, true);

			Sec.addReg(AVReg);
			// Add CPSR if the MI has.
			if (Idx != -1) {
				Fst.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Fst, MI.getOperand(Idx));
				Sec.addImm(MI.getOperand(Idx - 1).getImm());
				addOperand(Sec, MI.getOperand(Idx));
			}
			Fst.addMetadata(MDNFir);
			Sec.addMetadata(MDNSec);
		}

		return &MI;
	}
  MachineInstr *splitLDRSTRPre(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRPreImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitCommon(MachineBasicBlock &MBB, MachineInstr &MI,
                            unsigned NewOpc);
  MachineInstr *splitS(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned NewOpc, int Idx);
  MachineInstr *splitC(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned NewOpc, int Idx);
  MachineInstr *splitCS(MachineBasicBlock &MBB, MachineInstr &MI,
                        unsigned NewOpc, int Idx);
  /// True if the ARM instruction performs Shift_C().
  bool isShift_C(unsigned Opcode); // NOLINT(readability-identifier-naming)
  /// No matter what pattern of Load/Store is, change the Opcode to xxxi12.
  unsigned getLoadStoreOpcode(unsigned Opcode);
  /// If the MI is load/store which needs wback, it will return true.
  bool isLDRSTRPre(unsigned Opcode);
  MachineInstrBuilder &addOperand(MachineInstrBuilder &MIB, MachineOperand &MO,
                                  bool IsDef = false);

  MachineRegisterInfo *MRI;
  const ARMBaseInstrInfo *TII;
  LLVMContext *CTX;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMINSTRUCTIONSPLITTING_H
