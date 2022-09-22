//===- ARMArgumentRaiser.cpp - Binary raiser utility llvm-mctoll ----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMArgumentRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMArgumentRaiser.h"
#include "ARMSubtarget.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include <vector>

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

char ARMArgumentRaiser::ID = 0;

ARMArgumentRaiser::ARMArgumentRaiser(ARMModuleRaiser &CurrMR,
                                     MachineFunction *CurrMF,
                                     Function *CurrRF)
    : ARMRaiserBase(ID, CurrMR) {
  MF = CurrMF;
  RF = CurrRF;
  MFI = &MF->getFrameInfo();
  TII = MF->getSubtarget<ARMSubtarget>().getInstrInfo();
}

ARMArgumentRaiser::~ARMArgumentRaiser() {}

/// Change all return relative register operands to stack 0.
void ARMArgumentRaiser::updateReturnRegister(MachineFunction &MF) {
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.succ_empty()) {
      bool Loop = true;
      for (MachineBasicBlock::reverse_iterator IIter = MBB.rbegin(),
                                               IEnd = MBB.rend();
           (IIter != IEnd) && Loop; ++IIter) {
        MachineInstr &MI = *IIter;
        for (MachineInstr::mop_iterator OpIter = MI.operands_begin(),
                                        OpEnd = MI.operands_end();
             OpIter != OpEnd; OpIter++) {
          MachineOperand &MO = *OpIter;
          if (MO.isReg() && (MO.getReg() == ARM::R0)) {
            if (MO.isDef()) {
              MO.ChangeToFrameIndex(0);
              Loop = false;
              break;
            }
          }
        }
      }
    }
  }
}

/// Change all function arguments of registers into stack elements with same
/// indexes of arguments.
void ARMArgumentRaiser::updateParameterRegister(unsigned Reg,
                                                MachineBasicBlock &MBB) {
  for (MachineBasicBlock::iterator IIter = MBB.begin(), IEnd = MBB.end();
       IIter != IEnd;
       ++IIter) {
    MachineInstr &MI = *IIter;
    for (MachineInstr::mop_iterator OpIter = MI.operands_begin(),
                                    OpEnd = MI.operands_end();
         OpIter != OpEnd; OpIter++) {
      MachineOperand &MO = *OpIter;
      if (MO.isReg() && (MO.getReg() == Reg)) {
        if (MO.isUse()) {
          // The argument's index on frame starts from 1.
          // Such as R0 = 1, R1 = 2, R2 = 3, R3 = 4
          // For instance: R3 - R0 + 1 = 4
          MO.ChangeToFrameIndex(Reg - ARM::R0 + 1);
        } else
          return;
      }
    }
  }
}

/// Change rest of function arguments on stack frame into stack elements.
void ARMArgumentRaiser::updateParameterFrame(MachineFunction &MF) {

  for (MachineFunction::iterator MBBIter = MF.begin(), MBBEnd = MF.end();
       MBBIter != MBBEnd; ++MBBIter) {
    MachineBasicBlock &MBB = *MBBIter;

    for (MachineBasicBlock::iterator MIIter = MBB.begin(), MIEnd = MBB.end();
         MIIter != MIEnd; ++MIIter) {
      MachineInstr &MI = *MIIter;
      // Match pattern like ldr r1, [fp, #8].
      if (MI.getOpcode() == ARM::LDRi12 && MI.getNumOperands() > 2) {
        MachineOperand &MO = MI.getOperand(1);
        MachineOperand &MC = MI.getOperand(2);
        if (MO.isReg() && MO.getReg() == ARM::R11 && MC.isImm()) {
          // TODO: Need to check the imm is larger than 0 and it is align by
          // 4(32 bit).
          int Imm = MC.getImm();
          if (Imm >= 0) {
            int Idx = Imm / 4 - 2 + 5; // The index 0 is reserved to return
                                       // value. From 1 to 4 are the register
                                       // argument indices. Plus 5 to the index.
            MI.getOperand(1).ChangeToFrameIndex(Idx);
            MI.removeOperand(2);
          }
        }
      }
    }
  }
}

/// Move arguments which are passed by ARM registers(R0 - R3) from function
/// arg.x to corresponding registers in entry block.
void ARMArgumentRaiser::moveArgumentToRegister(unsigned Reg,
                                               MachineBasicBlock &PMBB) {
  const MCInstrDesc &InstrDesc = TII->get(ARM::MOVr);
  MachineInstrBuilder Builder = BuildMI(*MF, *(new DebugLoc()), InstrDesc);
  Builder.addDef(Reg);
  Builder.addFrameIndex(Reg - ARM::R0 + 1);
  PMBB.insert(PMBB.begin(), Builder.getInstr());
}

/// updateParameterInstr - Using newly created stack elements replace relative
/// operands in MachineInstr.
void ARMArgumentRaiser::updateParameterInstr(MachineFunction &MF) {
  // Move arguments to corresponding registers.
  MachineBasicBlock &EntryMBB = MF.front();
  switch (RF->arg_size()) {
  default:
    updateParameterFrame(MF);
    LLVM_FALLTHROUGH;
  case 4:
    moveArgumentToRegister(ARM::R3, EntryMBB);
    LLVM_FALLTHROUGH;
  case 3:
    moveArgumentToRegister(ARM::R2, EntryMBB);
    LLVM_FALLTHROUGH;
  case 2:
    moveArgumentToRegister(ARM::R1, EntryMBB);
    LLVM_FALLTHROUGH;
  case 1:
    moveArgumentToRegister(ARM::R0, EntryMBB);
    LLVM_FALLTHROUGH;
  case 0:
    break;
  }
}

bool ARMArgumentRaiser::raiseArgs() {
  LLVM_DEBUG(dbgs() << "ARMArgumentRaiser start.\n");

  int ArgIdx = 1;
  for (Function::arg_iterator ArgIter = RF->arg_begin(), ArgEnd = RF->arg_end();
       ArgIter != ArgEnd; ++ArgIter)
    ArgIter->setName("arg." + std::to_string(ArgIdx++));

  for (unsigned Idx = 0, End = RF->arg_size() + 1; Idx < End; ++Idx) {
    Align ALG(32);
    MFI->CreateStackObject(32, ALG, false);
  }

  updateParameterInstr(*MF);

  // For debugging.
  LLVM_DEBUG(MF->dump());
  LLVM_DEBUG(getRaisedFunction()->dump());
  LLVM_DEBUG(dbgs() << "ARMArgumentRaiser end.\n");

  return true;
}

bool ARMArgumentRaiser::runOnMachineFunction(MachineFunction &MF) {
  init();
  return raiseArgs();
}

#undef DEBUG_TYPE

extern "C" FunctionPass *createARMArgumentRaiser(ARMModuleRaiser &MR,
                                                 MachineFunction *MF,
                                                 Function *RF) {
  return new ARMArgumentRaiser(MR, MF, RF);
}
