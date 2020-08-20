//===- ARMEliminatePrologEpilog.cpp - Binary raiser utility llvm-mctoll ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMEliminatePrologEpilog class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMEliminatePrologEpilog.h"
#include "ARMSubtarget.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;

char ARMEliminatePrologEpilog::ID = 0;

ARMEliminatePrologEpilog::ARMEliminatePrologEpilog(ARMModuleRaiser &mr)
    : ARMRaiserBase(ID, mr) {}

ARMEliminatePrologEpilog::~ARMEliminatePrologEpilog() {}

void ARMEliminatePrologEpilog::init(MachineFunction *mf, Function *rf) {
  ARMRaiserBase::init(mf, rf);
}

/// Return true if an operand in the instrs vector matches the passed register
/// number, otherwise false.
bool ARMEliminatePrologEpilog::checkRegister(
    unsigned Reg, std::vector<MachineInstr *> &instrs) const {
  std::vector<MachineInstr *>::iterator it = instrs.begin();
  for (; it < instrs.end(); ++it) {
    MachineInstr *mi = *it;
    if (mi->mayStore()) {
      for (unsigned i = 0; i < mi->getNumOperands(); i++) {
        MachineOperand MO = mi->getOperand(i);

        // Compare the register number.
        if (MO.isReg() && MO.getReg() == Reg)
          return true;
      }
    }
  }
  return false;
}

/// Raise the function prolog.
///
/// Look for the following instructions and eliminate them:
///       str fp, [sp, #-4]!
///       add fp, sp, #0
///
///       sub sp, fp, #0
///       ldr fp, [sp], #4
/// AND
///       push {r11,lr}
///       add r11, sp, #4
///
///       sub sp, r11, #4
///       pop	{r11, pc}
/// AND
///       stmdb r13!, {r0-r3}
///       stmdb r13!, {r4-r12,r13,r14}
///
///       ldmia r13, {r4-r11, r13, r15}
/// AND
///       mov r12, r13
///       stmdb r13!, {r0-r3}
///       stmdb r13!, {r4-r12, r14}
///       sub r11, r12, #16
///
///       ldmdb r13, {r4-r11, r13, r15}
bool ARMEliminatePrologEpilog::eliminateProlog(MachineFunction &MF) const {
  std::vector<MachineInstr *> prologInstrs;
  MachineBasicBlock &frontMBB = MF.front();

  const ARMSubtarget &STI = MF.getSubtarget<ARMSubtarget>();
  const ARMBaseRegisterInfo *RegInfo = STI.getRegisterInfo();
  unsigned FramePtr = RegInfo->getFrameRegister(MF);

  for (MachineBasicBlock::iterator frontMBBIter = frontMBB.begin();
       frontMBBIter != frontMBB.end(); frontMBBIter++) {
    MachineInstr &curMachInstr = (*frontMBBIter);

    // Push the MOVr instruction
    if (curMachInstr.getOpcode() == ARM::MOVr) {
      if (curMachInstr.getOperand(0).isReg() &&
          curMachInstr.getOperand(0).getReg() == ARM::R11 &&
          curMachInstr.getOperand(1).isReg() &&
          curMachInstr.getOperand(1).getReg() == FramePtr)
        prologInstrs.push_back(&curMachInstr);
    }

    // Push the STORE instruction
    if (curMachInstr.mayStore()) {
      MachineOperand storeOperand = curMachInstr.getOperand(0);
      if (storeOperand.isReg() && storeOperand.getReg() == FramePtr) {
        prologInstrs.push_back(&curMachInstr);
      }
    }

    // Push the ADDri instruction
    // add Rx, sp, #imm ; This kind of patten ought to be eliminated.
    if (curMachInstr.getOpcode() == ARM::ADDri &&
        curMachInstr.getOperand(0).getReg() == ARM::R11 &&
        curMachInstr.getOperand(1).getReg() == FramePtr) {
      prologInstrs.push_back(&curMachInstr);
    }

    // Push the SUBri instruction
    if (curMachInstr.getOpcode() == ARM::SUBri &&
        curMachInstr.getOperand(0).getReg() == FramePtr &&
        curMachInstr.getOperand(1).getReg() == FramePtr) {
      prologInstrs.push_back(&curMachInstr);
    }

    // Push sub r11, r12, #16
    if (curMachInstr.getOpcode() == ARM::SUBri &&
        curMachInstr.getOperand(0).getReg() == ARM::R11 &&
        curMachInstr.getOperand(1).getReg() == ARM::R12) {
      prologInstrs.push_back(&curMachInstr);
    }
  }

  // Create the stack frame
  const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
  const MCPhysReg *CSRegs = TRI->getCalleeSavedRegs(&MF);

  std::vector<CalleeSavedInfo> CSI;
  for (unsigned i = 0; CSRegs[i]; ++i) {
    unsigned Reg = CSRegs[i];

    // Save register.
    if (checkRegister(Reg, prologInstrs)) {
      CSI.push_back(CalleeSavedInfo(Reg));
    }
  }

  const TargetFrameLowering *TFI = MF.getSubtarget().getFrameLowering();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  if (!TFI->assignCalleeSavedSpillSlots(MF, RegInfo, CSI)) {
    // If target doesn't implement this, use generic code.
    if (CSI.empty())
      return true; // Early exit if no callee saved registers are modified!

    unsigned NumFixedSpillSlots;
    const TargetFrameLowering::SpillSlot *FixedSpillSlots =
        TFI->getCalleeSavedSpillSlots(NumFixedSpillSlots);

    // Allocate stack slots for the registers that need to be saved and restored
    unsigned Offset = 0;
    for (auto &CS : CSI) {
      unsigned Reg = CS.getReg();
      const TargetRegisterClass *RC = RegInfo->getMinimalPhysRegClass(Reg);

      int FrameIdx;
      if (RegInfo->hasReservedSpillSlot(MF, Reg, FrameIdx)) {
        CS.setFrameIdx(FrameIdx);
        continue;
      }

      // Check if this physreg must be spilled to a particular stack slot for
      // this target
      const TargetFrameLowering::SpillSlot *FixedSlot = FixedSpillSlots;
      while (FixedSlot != FixedSpillSlots + NumFixedSpillSlots &&
             FixedSlot->Reg != Reg)
        ++FixedSlot;

      unsigned Size = RegInfo->getSpillSize(*RC);
      if (FixedSlot == FixedSpillSlots + NumFixedSpillSlots) {
        // Nope, just spill it anywhere convenient.
        Align Alignment(RegInfo->getSpillAlignment(*RC));

        // The alignment is the minimum of the desired alignment of the
        // TargetRegisterClass and the stack alignment, whichever is smaller.
        Alignment = std::min(Alignment, TFI->getStackAlign());
        FrameIdx = MFI.CreateStackObject(Size, Alignment, true);
        Offset += Size;

        // Set the object offset
        MFI.setObjectOffset(FrameIdx, MFI.getObjectOffset(FrameIdx) - Offset);
      } else {
        // Spill to the stack.
        FrameIdx = MFI.CreateFixedSpillStackObject(Size, FixedSlot->Offset);
      }

      // Set the frame index
      CS.setFrameIdx(FrameIdx);
    }
    MFI.setCalleeSavedInfo(CSI);
  }

  // Eliminate the instructions identified in function prologue
  unsigned int delInstSz = prologInstrs.size();
  for (unsigned int i = 0; i < delInstSz; i++) {
    frontMBB.erase(prologInstrs[i]);
  }

  return true;
}

bool ARMEliminatePrologEpilog::eliminateEpilog(MachineFunction &MF) const {
  const ARMSubtarget &STI = MF.getSubtarget<ARMSubtarget>();
  const ARMBaseRegisterInfo *RegInfo = STI.getRegisterInfo();
  const ARMBaseInstrInfo *TII = STI.getInstrInfo();
  unsigned FramePtr = RegInfo->getFrameRegister(MF);

  for (MachineBasicBlock &MBB : MF) {
    std::vector<MachineInstr *> epilogInstrs;
    // MBBI may be invalidated by the raising operation.
    for (MachineBasicBlock::iterator backMBBIter = MBB.begin();
         backMBBIter != MBB.end(); backMBBIter++) {
      MachineInstr &curMachInstr = (*backMBBIter);

      // Push the LOAD instruction
      if (curMachInstr.mayLoad()) {
        MachineOperand loadOperand = curMachInstr.getOperand(0);
        if (loadOperand.isReg() && loadOperand.getReg() == FramePtr) {
          // If the register list of current POP includes PC register,
          // it should be replaced with return instead of removed.
          if (curMachInstr.findRegisterUseOperandIdx(ARM::PC) != -1) {
            MachineInstrBuilder mib =
                BuildMI(MBB, &curMachInstr, DebugLoc(), TII->get(ARM::BX_RET));
            int cpsridx = curMachInstr.findRegisterUseOperandIdx(ARM::CPSR);
            if (cpsridx == -1) {
              mib.addImm(ARMCC::AL);
            } else {
              mib.add(curMachInstr.getOperand(cpsridx - 1))
                  .add(curMachInstr.getOperand(cpsridx));
            }
            mib.add(curMachInstr.getOperand(
                curMachInstr.getNumExplicitOperands() - 1));
          }
          epilogInstrs.push_back(&curMachInstr);
        }
      }

      // Push the LDR instruction
      if (curMachInstr.getOpcode() == ARM::LDR_POST_IMM &&
          curMachInstr.getOperand(1).getReg() == FramePtr) {
        epilogInstrs.push_back(&curMachInstr);
      }

      // Push the STR instruction
      if (curMachInstr.getOpcode() == ARM::STR_PRE_IMM &&
          curMachInstr.getOperand(0).getReg() == FramePtr) {
        epilogInstrs.push_back(&curMachInstr);
      }

      // Push the ADDri instruction
      if (curMachInstr.getOpcode() == ARM::ADDri &&
          curMachInstr.getOperand(0).isReg()) {
        if (curMachInstr.getOperand(0).getReg() == FramePtr) {
          epilogInstrs.push_back(&curMachInstr);
        }
      }

      // Push the SUBri instruction
      if (curMachInstr.getOpcode() == ARM::SUBri &&
          curMachInstr.getOperand(0).getReg() == FramePtr) {
        epilogInstrs.push_back(&curMachInstr);
      }

      if (curMachInstr.getOpcode() == ARM::MOVr) {
        if (curMachInstr.getOperand(1).isReg() &&
            curMachInstr.getOperand(1).getReg() == ARM::R11 &&
            curMachInstr.getOperand(0).isReg() &&
            curMachInstr.getOperand(0).getReg() == FramePtr)
          epilogInstrs.push_back(&curMachInstr);
      }
    }

    // Eliminate the instructions identified in function epilogue
    unsigned int delInstSz = epilogInstrs.size();
    for (unsigned int i = 0; i < delInstSz; i++) {
      MBB.erase(epilogInstrs[i]);
    }
  }

  return true;
}

/// Analyze stack size base on moving sp.
/// Patterns like:
/// sub	sp, sp, #28
void ARMEliminatePrologEpilog::analyzeStackSize(MachineFunction &mf) {
  if (mf.size() < 1)
    return;

  const MachineBasicBlock &mbb = mf.front();

  for (const MachineInstr &mi : mbb.instrs()) {
    if (mi.getOpcode() == ARM::SUBri && mi.getNumOperands() >= 3 &&
        mi.getOperand(0).isReg() && mi.getOperand(0).getReg() == ARM::SP &&
        mi.getOperand(1).isReg() && mi.getOperand(1).getReg() == ARM::SP &&
        mi.getOperand(2).isImm() && mi.getOperand(2).getImm() > 0) {
      mf.getFrameInfo().setStackSize(mi.getOperand(2).getImm());
      break;
    }
  }
}

/// Analyze frame adjustment base on the offset between fp and base sp.
/// Patterns like:
/// add	fp, sp, #8
void ARMEliminatePrologEpilog::analyzeFrameAdjustment(MachineFunction &mf) {
  if (mf.size() < 1)
    return;

  const MachineBasicBlock &mbb = mf.front();

  for (const MachineInstr &mi : mbb.instrs()) {
    if (mi.getOpcode() == ARM::ADDri && mi.getNumOperands() >= 3 &&
        mi.getOperand(0).isReg() && mi.getOperand(0).getReg() == ARM::R11 &&
        mi.getOperand(1).isReg() && mi.getOperand(1).getReg() == ARM::SP &&
        mi.getOperand(2).isImm() && mi.getOperand(2).getImm() > 0) {
      mf.getFrameInfo().setOffsetAdjustment(mi.getOperand(2).getImm());
      break;
    }
  }
}

bool ARMEliminatePrologEpilog::eliminate() {
  if (PrintPass)
    dbgs() << "ARMEliminatePrologEpilog start.\n";

  analyzeStackSize(*MF);
  analyzeFrameAdjustment(*MF);
  bool success = eliminateProlog(*MF);

  if (success) {
    success = eliminateEpilog(*MF);
  }

  // For debugging.
  if (PrintPass) {
    LLVM_DEBUG(MF->dump());
    LLVM_DEBUG(getCRF()->dump());
    dbgs() << "ARMEliminatePrologEpilog end.\n";
  }

  return !success;
}

bool ARMEliminatePrologEpilog::runOnMachineFunction(MachineFunction &mf) {
  bool rtn = false;
  init();
  rtn = eliminate();
  return rtn;
}

#ifdef __cplusplus
extern "C" {
#endif

FunctionPass *InitializeARMEliminatePrologEpilog(ARMModuleRaiser &mr) {
  return new ARMEliminatePrologEpilog(mr);
}

#ifdef __cplusplus
}
#endif
