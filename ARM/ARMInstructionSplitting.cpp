//===- ARMInstructionSplitting.cpp - Binary raiser utility llvm-mctoll ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMInstructionSplitting class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMInstructionSplitting.h"
#include "ARMBaseInstrInfo.h"
#include "ARMSubtarget.h"
#include "MCTargetDesc/ARMAddressingModes.h"
#include "llvm/CodeGen/MachineOperand.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

char ARMInstructionSplitting::ID = 0;

ARMInstructionSplitting::ARMInstructionSplitting(ARMModuleRaiser &CurrMR,
                                                 MachineFunction *CurrMF,
                                                 Function *CurrRF)
    : ARMRaiserBase(ID, CurrMR) {
  MF = CurrMF;
  RF = CurrRF;
  TII = MF->getSubtarget<ARMSubtarget>().getInstrInfo();
  MRI = &MF->getRegInfo();
  CTX = &getModule()->getContext();
}

ARMInstructionSplitting::~ARMInstructionSplitting() {}

/// Check if the MI has shift pattern.
unsigned ARMInstructionSplitting::checkisShifter(unsigned Opcode) {
  switch (Opcode) {
  case ARM::MOVsr:
  case ARM::MOVsi:
    return ARM::MOVr;
  case ARM::ADCrsi:
  case ARM::ADCrsr:
    return ARM::ADCrr;
  case ARM::ADDrsi:
  case ARM::ADDrsr:
    return ARM::ADDrr;
  case ARM::ANDrsi:
  case ARM::ANDrsr:
    return ARM::ANDrr;
  case ARM::BICrsr:
  case ARM::BICrsi:
    return ARM::BICrr;
  case ARM::CMNzrsi:
  case ARM::CMNzrsr:
    return ARM::CMNzrr;
  case ARM::CMPrsi:
  case ARM::CMPrsr:
    return ARM::CMPrr;
  case ARM::EORrsr:
  case ARM::EORrsi:
    return ARM::EORrr;
  case ARM::MVNsr:
  case ARM::MVNsi:
    return ARM::MVNr;
  case ARM::ORRrsi:
  case ARM::ORRrsr:
    return ARM::ORRrr;
  case ARM::RSBrsi:
  case ARM::RSBrsr:
    return ARM::RSBrr;
  case ARM::SUBrsi:
  case ARM::SUBrsr:
    return ARM::SUBrr;
  case ARM::TEQrsr:
  case ARM::TEQrsi:
    return ARM::TEQrr;
  case ARM::TSTrsr:
  case ARM::TSTrsi:
    return ARM::TSTrr;
  default:
    return 0;
  }
}

/// If the MI is load/store which needs wback, it will return true.
bool ARMInstructionSplitting::isLDRSTRPre(unsigned Opcode) {
  switch (Opcode) {
  case ARM::LDR_PRE_REG:
  case ARM::LDR_PRE_IMM:
  case ARM::LDRB_PRE_REG:
  case ARM::LDRB_PRE_IMM:
  case ARM::STR_PRE_REG:
  case ARM::STR_PRE_IMM:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_PRE_IMM:
    return true;
  default:
    return false;
  }
}

/// No matter what pattern of Load/Store is, change the Opcode to xxxi12.
unsigned ARMInstructionSplitting::getLoadStoreOpcode(unsigned Opcode) {
  switch (Opcode) {
  case ARM::LDRrs:
  case ARM::LDRi12:
  case ARM::LDR_PRE_REG:
  case ARM::LDR_PRE_IMM:
    return ARM::LDRi12;
  case ARM::LDRBrs:
  case ARM::LDRBi12:
  case ARM::LDRB_PRE_REG:
  case ARM::LDRB_PRE_IMM:
    return ARM::LDRBi12;
  case ARM::STRrs:
  case ARM::STRi12:
  case ARM::STR_PRE_REG:
  case ARM::STR_PRE_IMM:
    return ARM::STRi12;
  case ARM::STRBrs:
  case ARM::STRBi12:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_PRE_IMM:
    return ARM::STRBi12;
  default:
    return 0;
  }
}

/// True if the ARM instruction performs Shift_C().
bool ARMInstructionSplitting::isShift_C(unsigned Opcode) {
  switch (Opcode) {
  case ARM::ANDrsr:
  case ARM::ANDrsi:
  case ARM::BICrsr:
  case ARM::BICrsi:
  case ARM::EORrsr:
  case ARM::EORrsi:
  case ARM::MVNsr:
  case ARM::MVNsi:
  case ARM::ORRrsr:
  case ARM::ORRrsi:
  case ARM::TEQrsr:
  case ARM::TEQrsi:
  case ARM::TSTrsr:
  case ARM::TSTrsi:
    return true;
  default:
    return false;
  }
}

/// Get the shift opcode in MI.
unsigned ARMInstructionSplitting::getShiftOpcode(ARM_AM::ShiftOpc SOpc,
                                                 unsigned OffSet) {
  switch (SOpc) {
  case ARM_AM::asr: {
    if (OffSet != 0)
      return ARM::ASRi;
    else
      return ARM::ASRr;
  }
  case ARM_AM::lsl: {
    if (OffSet != 0)
      return ARM::LSLi;
    else
      return ARM::LSLr;
  }
  case ARM_AM::lsr: {
    if (OffSet != 0)
      return ARM::LSRi;
    else
      return ARM::LSRr;
  }
  case ARM_AM::ror: {
    if (OffSet != 0)
      return ARM::RORi;
    else
      return ARM::RORr;
  }
  case ARM_AM::rrx:
    return ARM::RRX;
  case ARM_AM::no_shift:
  default:
    return 0;
  }
}

MachineInstrBuilder &
ARMInstructionSplitting::addOperand(MachineInstrBuilder &MIB,
                                    MachineOperand &MO, bool IsDef) {
  switch (MO.getType()) {
  default:
    assert(false && "Unsupported MachineOperand type!");
    break;
  case MachineOperand::MO_Register: {
    if (IsDef)
      MIB.addDef(MO.getReg());
    else
      MIB.addUse(MO.getReg());
  } break;
  case MachineOperand::MO_FrameIndex: {
    MIB.addFrameIndex(MO.getIndex());
  } break;
  }

  return MIB;
}

/// Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, #+/-<imm>]! to:
/// ADD Rn, Rn, #imm
/// LDRxxx/STRxxx Rt, [Rn]
MachineInstr *ARMInstructionSplitting::splitLDRSTRPreImm(MachineBasicBlock &MBB,
                                                         MachineInstr &MI) {
  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);
  MachineOperand &Rs = MI.getOperand(3);

  // MI is splitted into 2 instructions.
  // So get Metadata for the first instruction.
  ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
  MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

  // Get Metadata for the second instruction.
  ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
  MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  // Add Rm,[Rm, #imm]!
  MachineInstrBuilder Fst =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
  addOperand(Fst, Rm, true);
  addOperand(Fst, Rm);
  Fst.addImm(Rs.getImm());

  MachineInstrBuilder Sec =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
  if (MI.mayStore())
    // STRxxx Rn, [Rm]
    addOperand(Sec, Rn);
  else if (MI.mayLoad())
    // LDRxxx Rd, [Rm]
    addOperand(Sec, Rd, true);
  addOperand(Sec, Rm);

  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Add CPSR if the MI has.
  if (Idx != -1) {
    Fst.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Fst, MI.getOperand(Idx));
    Sec.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Sec, MI.getOperand(Idx));
  }
  Fst.addMetadata(N_fst);
  Sec.addMetadata(N_sec);
  return &MI;
}

/// Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>{, <shift>}]! to:
/// Rm shift #imm, but write result to VReg.
/// Add Rn, Rm
/// LDRxxx/STRxxx Rt, [Rn]
MachineInstr *ARMInstructionSplitting::splitLDRSTRPre(MachineBasicBlock &MBB,
                                                      MachineInstr &MI) {
  unsigned Simm = MI.getOperand(4).getImm();
  unsigned SOffSet = ARM_AM::getAM2Offset(Simm);
  ARM_AM::ShiftOpc SOpc = ARM_AM::getAM2ShiftOpc(Simm);
  Register SVReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);

  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);
  MachineOperand &Rs = MI.getOperand(3);
  unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);

  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
  MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

  // Get Metadata for the second instruction.
  ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
  MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

  // Get Metadata for the third instruction.
  ConstantAsMetadata *CMD_thd = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 2, false)));
  MDNode *N_thd = MDNode::get(*CTX, CMD_thd);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  if (SOffSet > 0) {
    // LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>{, <shift>}]!

    // Rs shift #imm and write result to VReg.
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rs);
    Fst.addImm(SOffSet);

    // Add Rm, VReg
    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Sec, Rm, true);
    addOperand(Sec, Rm);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      // STRxxx Rn, [Rm]
      addOperand(Thd, Rn);
    else if (MI.mayLoad())
      // LDRxxx Rd, [Rm]
      addOperand(Thd, Rd, true);
    addOperand(Thd, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
    Thd.addMetadata(N_thd);
  } else if (ShiftOpc == ARM::RRX) {
    // Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>, RRX]!
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rs);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Sec, Rm, true);
    addOperand(Sec, Rm);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Thd, Rn);
    else if (MI.mayLoad())
      addOperand(Thd, Rd, true);
    addOperand(Thd, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
    Thd.addMetadata(N_thd);
  } else {
    // Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>]!
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Fst, Rm, true);
    addOperand(Fst, Rm);
    addOperand(Fst, Rs);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Sec, Rn);
    else if (MI.mayLoad())
      addOperand(Sec, Rd, true);
    addOperand(Sec, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
    }
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
  }
  return &MI;
}

/// Split LDRxxx/STRxxx<c><q> <Rd>, [<Rn>, +/-<#imm>] to:
/// Add VReg, Rn, #imm
/// LDRxxx/STRxxx Rd, [VReg]
MachineInstr *ARMInstructionSplitting::splitLDRSTRImm(MachineBasicBlock &MBB,
                                                      MachineInstr &MI) {
  Register VReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);
  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);

  // The MI is splitted into 2 instructions.
  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
  MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
  MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  // Add VReg, Rn, #imm
  MachineInstrBuilder Fst =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr), VReg);
  addOperand(Fst, Rn);
  Fst.addImm(Rm.getImm());

  // LDRxxx/STRxxx Rd, [VReg]
  MachineInstrBuilder Sec =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
  if (MI.mayStore())
    addOperand(Sec, Rd);
  else
    addOperand(Sec, Rd, true);
  Sec.addReg(VReg);

  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Add CPSR if the MI has.
  if (Idx != -1) {
    Fst.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Fst, MI.getOperand(Idx));
    Sec.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Sec, MI.getOperand(Idx));
  }
  Fst.addMetadata(N_fst);
  Sec.addMetadata(N_sec);
  return &MI;
}

/// Split LDRxxx/STRxxx<c><q> <Rd>, [<Rn>, +/-<Rm>{, <shift>}] to:
/// Rm shift #imm, but write result to VReg.
/// Add VReg, Rn, Rm
/// LDRxxx/STRxxx Rd, [VReg]
MachineInstr *ARMInstructionSplitting::splitLDRSTR(MachineBasicBlock &MBB,
                                                   MachineInstr &MI) {
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
  ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
  MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

  // Get Metadata for the second insturction.
  ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
  MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

  // Get Metadata for the third insturction.
  ConstantAsMetadata *CMD_thd = ConstantAsMetadata::get(
      ConstantInt::get(*CTX, llvm::APInt(64, 2, false)));
  MDNode *N_thd = MDNode::get(*CTX, CMD_thd);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  if (SOffSet > 0) {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm, shift]
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rm);
    Fst.addImm(SOffSet);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr), AVReg);
    addOperand(Sec, Rn);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
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
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
    Thd.addMetadata(N_thd);
  } else if (ShiftOpc == ARM::RRX) {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm, rrx]
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rm);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr), AVReg);
    addOperand(Sec, Rn);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
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
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
    Thd.addMetadata(N_thd);
  } else {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm]
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr), AVReg);
    addOperand(Fst, Rn);
    addOperand(Fst, Rm);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
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
    Fst.addMetadata(N_fst);
    Sec.addMetadata(N_sec);
  }
  return &MI;
}

/// Split 'Opcode Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMInstructionSplitting::splitCommon(MachineBasicBlock &MBB,
                                                   MachineInstr &MI,
                                                   unsigned NewOpc) {
  MachineInstr *ResMI = nullptr;
  for (unsigned i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isImm()) {
      unsigned Simm = MI.getOperand(i).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);

      Register VReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);
      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(i - 2);
        MachineOperand &Rm = MI.getOperand(i - 1);

        ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
        MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

        ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
        MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

        if (SOffSet) {
          // Split Opcode Rd, Rn, Rm, shift #imm

          // Rm shifts SOffset and writes result to VReg.
          MachineInstrBuilder Fst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
          addOperand(Fst, Rm);
          Fst.addImm(SOffSet);
          Fst.addMetadata(N_fst);

          // Build 'opcode Rd, Rn, VReg'
          MachineInstrBuilder Sec =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
          addOperand(Sec, Rd, true);
          for (unsigned N = 1; N < (i - 1); N++) {
            addOperand(Sec, MI.getOperand(N));
          }
          Sec.addReg(VReg);
          Sec.addMetadata(N_sec);
        } else {
          if (ShiftOpc == ARM::RRX) {
            // Split 'opcode Rd, Rn, Rm, RRX'
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addMetadata(N_fst);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < i - 1; N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addMetadata(N_sec);
          } else {
            // Split 'opcode Rd, Rn, Rm, shift Rs'

            // Build 'ShiftOpc VReg, Rn, Rm'
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rn);
            addOperand(Fst, Rm);
            Fst.addMetadata(N_fst);

            // Build 'opcode Rd, Rn, VReg'
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (i - 2); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addMetadata(N_sec);
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<s> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMInstructionSplitting::splitS(MachineBasicBlock &MBB,
                                              MachineInstr &MI, unsigned NewOpc,
                                              int Idx) {
  MachineInstr *ResMI = nullptr;
  for (unsigned i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isImm()) {
      unsigned Simm = MI.getOperand(i).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
        MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

        ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
        MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(i - 2);
        MachineOperand &Rm = MI.getOperand(i - 1);

        // C flag is affected by Shift_c() if isShift_C is true.
        if (isShift_C(MI.getOpcode())) {
          if (SOffSet) {
            // Split opcode<s> Rd, Rn, Rm, shift #imm.

            // Rm shift #imm and  the new MI updates CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(ARMCC::AL);
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(N_fst);

            // Build 'opcode<s> Rd, Rn, VReg'
            // The new MI updates CPSR.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (i - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(ARMCC::AL);
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(N_sec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s> Rd, Rn, Rm, RRX.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(N_fst);
              // XXX: RRX implicit CPSR, how to add cpsr?

              // Build base instructions
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(N_sec);
            } else {
              // Split opcode<s> Rd, Rn, Rm, shift Rs.
              // The new MI updates CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(ARMCC::AL);
              addOperand(Fst, MI.getOperand(Idx));
              Fst.addMetadata(N_fst);

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(N_sec);
            }
          }
        } else {
          if (SOffSet) {
            // Split opcode<s> Rd, Rn, Rm, shift #imm.

            // Rm shift #imm,  and the new MI doesn't update CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addMetadata(N_fst);

            // Build 'opcode<s> Rd, Rn, VReg'
            // The new MI updates CPSR.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (i - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(ARMCC::AL);
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(N_sec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s> Rd, Rn, Rm, rrx.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(N_fst);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(N_sec);
            } else {
              // Split opcode<s> Rd, Rn, Rm, shift Rs.

              // Rm shift reg,  and the new MI doesn't update CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addMetadata(N_fst);

              // Build 'opcode<s> Rd, Rn, VReg'
              // The new MI updates CPSR.
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(N_sec);
            }
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<c> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMInstructionSplitting::splitC(MachineBasicBlock &MBB,
                                              MachineInstr &MI, unsigned NewOpc,
                                              int Idx) {
  MachineInstr *ResMI = nullptr;
  for (unsigned i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isImm()) {
      unsigned Simm = MI.getOperand(i).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(i - 2);
        MachineOperand &Rm = MI.getOperand(i - 1);

        ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
        MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

        ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
        MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

        if (SOffSet) {
          // Split opcode<c> Rd, Rn, Rm, shift #imm
          // The new MI checks CondCode.

          MachineInstrBuilder Fst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
          addOperand(Fst, Rm);
          Fst.addImm(SOffSet);
          Fst.addImm(MI.getOperand(Idx - 1).getImm());
          addOperand(Fst, MI.getOperand(Idx));
          Fst.addMetadata(N_fst);

          MachineInstrBuilder Sec =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
          addOperand(Sec, Rd, true);
          for (unsigned N = 1; N < (i - 1); N++) {
            addOperand(Sec, MI.getOperand(N));
          }
          Sec.addReg(VReg);
          Sec.addImm(MI.getOperand(Idx - 1).getImm());
          addOperand(Sec, MI.getOperand(Idx));
          Sec.addMetadata(N_sec);
        } else {
          if (ShiftOpc == ARM::RRX) {
            // Split opcode<c> Rd, Rn, Rm, RRX
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addMetadata(N_fst);
            // XXX: RRX implicit CPSR, how to add cpsr?

            // Build base instructions
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (i - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(N_sec);
          } else {
            // Split opcode<c> Rd, Rn, Rm, shift Rs
            // The new MI checks CondCode.

            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rn);
            addOperand(Fst, Rm);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(N_fst);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (i - 2); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(N_sec);
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<s><c> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMInstructionSplitting::splitCS(MachineBasicBlock &MBB,
                                               MachineInstr &MI,
                                               unsigned NewOpc, int Idx) {
  MachineInstr *ResMI = nullptr;
  for (unsigned i = 0; i < MI.getNumOperands(); i++) {
    if (MI.getOperand(i).isImm()) {
      unsigned Simm = MI.getOperand(i).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MRI->createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(i - 2);
        MachineOperand &Rm = MI.getOperand(i - 1);

        ConstantAsMetadata *CMD_fst = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 0, false)));
        MDNode *N_fst = MDNode::get(*CTX, CMD_fst);

        ConstantAsMetadata *CMD_sec = ConstantAsMetadata::get(
            ConstantInt::get(*CTX, llvm::APInt(64, 1, false)));
        MDNode *N_sec = MDNode::get(*CTX, CMD_sec);

        // C flag is affected by Shift_c() if isShift_C is true.
        if (isShift_C(MI.getOpcode())) {
          if (SOffSet) {
            // Split opcode<s><c> Rd, Rn, Rm, shift #imm

            // The new MI both updates CPSR and checks CondCode.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            addOperand(Fst, MI.getOperand(Idx + 1));
            Fst.addMetadata(N_fst);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (i - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            addOperand(Sec, MI.getOperand(Idx + 1));
            Sec.addMetadata(N_sec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s><c> Rd, Rn, Rm, RRX
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(N_fst);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(N_sec);
            } else {
              // Split opcode<s><c> Rd, Rn, Rm, shift Rs

              // The new MI both updates CPSR and checks CondCode.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Fst, MI.getOperand(Idx));
              addOperand(Fst, MI.getOperand(Idx + 1));
              Fst.addMetadata(N_fst);

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(N_sec);
            }
          }
        } else {
          // Shifter doesn't update cpsr
          if (SOffSet) {
            // Split 'opcode<s><c> Rd, Rn, Rm, shift #imm'

            // Rm shifts #imm
            // The new MI checks CondCode, doesn't update CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(N_fst);

            // Build 'newOpc<s><c> Rd, Rn, VReg'
            // The new MI both updates CPSR and checks CondCode.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (i - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            addOperand(Sec, MI.getOperand(Idx + 1));
            Sec.addMetadata(N_sec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s><c> Rd, Rn, Rm, RRX
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(N_fst);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(N_sec);
            } else {
              // Split opcode<s><c> Rd, Rn, Rm, shift Rs

              // Rm shift #imm.
              // The new MI checks CondCode, doesn't update CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Fst, MI.getOperand(Idx));
              Fst.addMetadata(N_fst);

              // Build 'newOpc<s><c> Rd, Rn, VReg'
              // The new MI both updates CPSR and checks CondCode.
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (i - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(N_sec);
            }
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

bool ARMInstructionSplitting::split() {
  LLVM_DEBUG(dbgs() << "ARMInstructionSplitting start.\n");

  std::vector<MachineInstr *> RemoveList;
  for (MachineBasicBlock &MBB : *MF) {
    for (MachineBasicBlock::iterator I = MBB.begin(), E = MBB.end(); I != E;
         ++I) {
      MachineInstr &MI = *I;
      MachineInstr *RemoveMI = nullptr;

      unsigned Opcode, NewOpc;
      Opcode = MI.getOpcode();
      NewOpc = checkisShifter(Opcode);

      // Need to split
      if (getLoadStoreOpcode(Opcode)) {
        // Split the MI about Load and Store.

        // TODO: LDRSH/LDRSB/LDRH/LDRD split.
        if (isLDRSTRPre(Opcode)) {
          if (MI.getOperand(3).isReg())
            RemoveMI = splitLDRSTRPre(MBB, MI);
          else if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() != 0)
            RemoveMI = splitLDRSTRPreImm(MBB, MI);
          if (RemoveMI)
            RemoveList.push_back(RemoveMI);
        } else if (MI.getOperand(1).isReg() &&
                   MI.getOperand(1).getReg() != ARM::SP &&
                   MI.getOperand(1).getReg() != ARM::PC) {
          if (MI.getOperand(2).isReg())
            RemoveMI = splitLDRSTR(MBB, MI);
          else if (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() != 0)
            RemoveMI = splitLDRSTRImm(MBB, MI);
          if (RemoveMI)
            RemoveList.push_back(RemoveMI);
        }
      } else if (NewOpc) {
        // Split the MI except Load and Store.

        bool UpdateCPSR = false;
        bool CondCode = false;
        int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);

        // Check if MI contains CPSR
        if (Idx != -1) {
          if (MI.getOperand(Idx + 1).isReg() &&
              MI.getOperand(Idx + 1).getReg() == ARM::CPSR) {
            UpdateCPSR = true;
            CondCode = true;
          } else if (MI.getOperand(Idx - 1).isImm() &&
                     MI.getOperand(Idx - 1).getImm() != ARMCC::AL) {
            CondCode = true;
          } else
            UpdateCPSR = true;
        }

        if (!UpdateCPSR && !CondCode)
          // Split the MI has no cpsr.
          RemoveMI = splitCommon(MBB, MI, NewOpc);
        else if (UpdateCPSR && !CondCode)
          // Split the MI updates cpsr.
          RemoveMI = splitS(MBB, MI, NewOpc, Idx);
        else if (!UpdateCPSR && CondCode)
          // Split the MI checks CondCode.
          RemoveMI = splitC(MBB, MI, NewOpc, Idx);
        else
          // Split the MI both updates cpsr and check CondCode
          RemoveMI = splitCS(MBB, MI, NewOpc, Idx);

        if (RemoveMI)
          RemoveList.push_back(RemoveMI);
      }
    }
  }

  // Remove old MI.
  for (MachineInstr *MI : RemoveList)
    MI->removeFromParent();

  // For debugging.
  LLVM_DEBUG(MF->dump());
  LLVM_DEBUG(getRaisedFunction()->dump());
  LLVM_DEBUG(dbgs() << "ARMInstructionSplitting end.\n");

  return true;
}

bool ARMInstructionSplitting::runOnMachineFunction(MachineFunction &MF) {
  init();
  return split();
}

#undef DEBUG_TYPE

extern "C" FunctionPass *createARMInstructionSplitting(ARMModuleRaiser &MR,
                                                       MachineFunction *MF,
                                                       Function *RF) {
  return new ARMInstructionSplitting(MR, MF, RF);
}
