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
#include <vector>

using namespace llvm;

char ARMArgumentRaiser::ID = 0;

ARMArgumentRaiser::ARMArgumentRaiser(ARMModuleRaiser &mr)
    : ARMRaiserBase(ID, mr) {}

ARMArgumentRaiser::~ARMArgumentRaiser() {}

void ARMArgumentRaiser::init(MachineFunction *mf, Function *rf) {
  ARMRaiserBase::init(mf, rf);
  MFI = &MF->getFrameInfo();
  TII = MF->getSubtarget<ARMSubtarget>().getInstrInfo();
}

/// Change all return relative register operands to stack 0.
void ARMArgumentRaiser::updateReturnRegister(MachineFunction &mf) {
  for (MachineBasicBlock &mbb : mf) {
    if (mbb.succ_empty()) {
      bool loop = true;
      for (MachineBasicBlock::reverse_iterator ii = mbb.rbegin(),
                                               ie = mbb.rend();
           (ii != ie) && loop; ++ii) {
        MachineInstr &mi = *ii;
        for (MachineInstr::mop_iterator oi = mi.operands_begin(),
                                        oe = mi.operands_end();
             oi != oe; oi++) {
          MachineOperand &mo = *oi;
          if (mo.isReg() && (mo.getReg() == ARM::R0)) {
            if (mo.isDef()) {
              mo.ChangeToFrameIndex(0);
              loop = false;
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
void ARMArgumentRaiser::updateParameterRegister(unsigned reg,
                                                MachineBasicBlock &mbb) {
  for (MachineBasicBlock::iterator ii = mbb.begin(), ie = mbb.end(); ii != ie;
       ++ii) {
    MachineInstr &mi = *ii;
    for (MachineInstr::mop_iterator oi = mi.operands_begin(),
                                    oe = mi.operands_end();
         oi != oe; oi++) {
      MachineOperand &mo = *oi;
      if (mo.isReg() && (mo.getReg() == reg)) {
        if (mo.isUse()) {
          // The argument's index on frame starts from 1.
          // Such as R0 = 1, R1 = 2, R2 = 3, R3 = 4
          // For instance: R3 - R0 + 1 = 4
          mo.ChangeToFrameIndex(reg - ARM::R0 + 1);
        } else
          return;
      }
    }
  }
}

/// Change rest of function arguments on stack frame into stack elements.
void ARMArgumentRaiser::updateParameterFrame(MachineFunction &mf) {

  for (MachineFunction::iterator mbbi = mf.begin(), mbbe = mf.end();
       mbbi != mbbe; ++mbbi) {
    MachineBasicBlock &mbb = *mbbi;

    for (MachineBasicBlock::iterator mii = mbb.begin(), mie = mbb.end();
         mii != mie; ++mii) {
      MachineInstr &mi = *mii;
      // Match pattern like ldr r1, [fp, #8].
      if (mi.getOpcode() == ARM::LDRi12 && mi.getNumOperands() > 2) {
        MachineOperand &mo = mi.getOperand(1);
        MachineOperand &mc = mi.getOperand(2);
        if (mo.isReg() && mo.getReg() == ARM::R11 && mc.isImm()) {
          // TODO: Need to check the imm is larger than 0 and it is align by
          // 4(32 bit).
          int imm = mc.getImm();
          if (imm >= 0) {
            int idx = imm / 4 - 2 + 5; // The index 0 is reserved to return
                                       // value. From 1 to 4 are the register
                                       // argument indices. Plus 5 to the index.
            mi.getOperand(1).ChangeToFrameIndex(idx);
            mi.RemoveOperand(2);
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
  const MCInstrDesc &mcInstrDesc = TII->get(ARM::MOVr);
  MachineInstrBuilder builder = BuildMI(*MF, *(new DebugLoc()), mcInstrDesc);
  builder.addDef(Reg);
  builder.addFrameIndex(Reg - ARM::R0 + 1);
  PMBB.insert(PMBB.begin(), builder.getInstr());
}

/// updateParameterInstr - Using newly created stack elements replace relative
/// operands in MachineInstr.
void ARMArgumentRaiser::updateParameterInstr(MachineFunction &mf) {
  Function *fn = getCRF();
  // Move arguments to corresponding registers.
  MachineBasicBlock &EntryMBB = mf.front();
  switch (fn->arg_size()) {
  default:
    updateParameterFrame(mf);
  case 4:
    moveArgumentToRegister(ARM::R3, EntryMBB);
  case 3:
    moveArgumentToRegister(ARM::R2, EntryMBB);
  case 2:
    moveArgumentToRegister(ARM::R1, EntryMBB);
  case 1:
    moveArgumentToRegister(ARM::R0, EntryMBB);
  case 0:
    break;
  }
}

int ARMArgumentRaiser::genStackObject(int idx) {
  return MFI->CreateStackObject(1, idx, false, nullptr);
}

bool ARMArgumentRaiser::raiseArgs() {
  if (PrintPass)
    dbgs() << "ARMArgumentRaiser start.\n";

  Function *fn = getCRF();

  int argidx = 1;
  for (Function::arg_iterator argi = fn->arg_begin(), arge = fn->arg_end();
       argi != arge; ++argi) {
    argi->setName("arg." + std::to_string(argidx++));
  }

  for (unsigned i = 0, e = fn->arg_size() + 1; i < e; ++i)
    genStackObject(i);

  updateParameterInstr(*MF);

  // For debugging.
  if (PrintPass) {
    MF->dump();
    getCRF()->dump();
    dbgs() << "ARMArgumentRaiser end.\n";
  }

  return true;
}

bool ARMArgumentRaiser::runOnMachineFunction(MachineFunction &mf) {
  bool rtn = false;
  init();
  rtn = raiseArgs();
  return rtn;
}

#ifdef __cplusplus
extern "C" {
#endif

FunctionPass *InitializeARMArgumentRaiser(ARMModuleRaiser &mr) {
  return new ARMArgumentRaiser(mr);
}

#ifdef __cplusplus
}
#endif
