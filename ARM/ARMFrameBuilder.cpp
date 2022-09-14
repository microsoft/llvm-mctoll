//===- ARMFrameBuilder.cpp - Binary raiser utility llvm-mctoll ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMFrameBuilder class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMFrameBuilder.h"
#include "ARMSubtarget.h"
#include "llvm/ADT/DenseMap.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

char ARMFrameBuilder::ID = 0;

ARMFrameBuilder::ARMFrameBuilder(ARMModuleRaiser &CurrMR,
                                 MachineFunction *CurrMF,
                                 Function *CurrRF)
    : ARMRaiserBase(ID, CurrMR) {
  MF = CurrMF;
  RF = CurrRF;
  MFI = &MF->getFrameInfo();
  Module *M = getModule();
  CTX = &M->getContext();
  DLT = &M->getDataLayout();
}

ARMFrameBuilder::~ARMFrameBuilder() {}

static bool isLoadOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::LDRi12:
  case ARM::LDRH:
  case ARM::LDRSH:
  case ARM::LDRBi12:
    return true;
  }
}

static bool isStoreOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::STRi12:
  case ARM::STRH:
  case ARM::STRBi12:
    return true;
  }
}

static bool isAddOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::ADDri:
    return true;
  }
}

static inline bool isHalfwordOP(unsigned Opcode) {
  bool Res;
  switch (Opcode) {
  default:
    Res = false;
    break;
  case ARM::STRH:
  case ARM::LDRH:
  case ARM::LDRSH:
    Res = true;
    break;
  }
  return Res;
}

unsigned ARMFrameBuilder::getBitCount(unsigned Opcode) {
  unsigned Ret;

  switch (Opcode) {
  default:
    Ret = Log2(DLT->getStackAlignment());
    break;
  case ARM::LDRi12:
  case ARM::STRi12:
    Ret = 4;
    break;
  case ARM::LDRBi12:
  case ARM::STRBi12:
    Ret = 1;
    break;
  case ARM::STRH:
  case ARM::LDRH:
  case ARM::LDRSH:
    Ret = 2;
    break;
  case ARM::ADDri:
    Ret = 4;
    break;
  }

  return Ret;
}

Type *ARMFrameBuilder::getStackType(unsigned Size) {
  Type *T = nullptr;
  Module *M = getModule();

  switch (Size) {
  default:
    T = Type::getIntNTy(M->getContext(),
                        M->getDataLayout().getPointerSizeInBits());
    break;
  case 8:
    T = Type::getInt64Ty(*CTX);
    break;
  case 4:
    T = Type::getInt32Ty(*CTX);
    break;
  case 2:
    T = Type::getInt16Ty(*CTX);
    break;
  case 1:
    T = Type::getInt8Ty(*CTX);
    break;
  }

  return T;
}

/// Replace common regs assigned by SP to SP.
/// Patterns like:
/// mov r5, sp
/// ldr r3, [r5, #4]
/// In this case, r5 should be replace by sp.
bool ARMFrameBuilder::replaceNonSPBySP(MachineInstr &MI) {
  if (MI.getOpcode() == ARM::MOVr) {
    if (MI.getOperand(1).isReg() && MI.getOperand(1).getReg() == ARM::SP) {
      if (MI.getOperand(0).isReg() && MI.getOperand(0).isDef()) {
        RegAssignedBySP.push_back(MI.getOperand(0).getReg());
        return true;
      }
    }
  }

  // Replace regs which are assigned by sp.
  for (MachineOperand &MO : MI.uses()) {
    for (unsigned Odx : RegAssignedBySP) {
      if (MO.isReg() && MO.getReg() == Odx) {
        MO.ChangeToRegister(ARM::SP, false);
      }
    }
  }

  // Record regs which are assigned by sp.
  for (MachineOperand &MO : MI.defs()) {
    for (SmallVector<unsigned, 16>::iterator I = RegAssignedBySP.begin();
         I != RegAssignedBySP.end();) {
      if (MO.isReg() && MO.getReg() == *I) {
        RegAssignedBySP.erase(I);
      } else
        ++I;
    }
  }

  return false;
}

/// Analyze frame index of stack operands.
/// Some patterns like:
/// ldr r3, [sp, #12]
/// str r4, [fp, #-8]
/// add r0, sp, #imm
int64_t ARMFrameBuilder::identifyStackOp(const MachineInstr &MI) {
  unsigned Opc = MI.getOpcode();
  if (!isLoadOP(Opc) && !isStoreOP(Opc) && !isAddOP(Opc))
    return -1;

  if (MI.getNumOperands() < 3)
    return -1;

  int64_t Offset = -1;
  const MachineOperand &MO = MI.getOperand(1);

  if (!MO.isReg())
    return -1;

  if (isHalfwordOP(Opc))
    Offset = MI.getOperand(3).getImm();
  else
    Offset = MI.getOperand(2).getImm();

  if (MO.getReg() == ARM::SP && Offset >= 0)
    return Offset;

  if (MO.getReg() == ARM::R11) {
    if (Offset > 0) {
      if (isHalfwordOP(Opc))
        Offset = 0 - static_cast<int64_t>(static_cast<int8_t>(Offset));
      else
        return -1;
    }
    return MFI->getStackSize() + Offset + MFI->getOffsetAdjustment();
  }

  return -1;
}

/// Find out all of frame relative operands, and update them.
void ARMFrameBuilder::searchStackObjects(MachineFunction &MF) {
  // <SPOffset, frame_element_ptr>
  std::map<int64_t, StackElement *, std::greater<int64_t>> SPOffElementMap;
  DenseMap<MachineInstr *, StackElement *> InstrToElementMap;

  std::vector<MachineInstr *> RemoveList;
  for (MachineFunction::iterator MBBIter = MF.begin(), MBBEnd = MF.end();
       MBBIter != MBBEnd; ++MBBIter) {
    for (MachineBasicBlock::iterator MIIter = MBBIter->begin(),
                                     MIEnd = MBBIter->end();
         MIIter != MIEnd; ++MIIter) {
      MachineInstr &MI = *MIIter;

      if (replaceNonSPBySP(MI)) {
        RemoveList.push_back(&MI);
        continue;
      }

      int64_t Off = identifyStackOp(MI);
      if (Off >= 0) {
        StackElement *SE = nullptr;
        if (SPOffElementMap.count(Off) == 0) {
          SE = new StackElement();
          SE->Size = getBitCount(MI.getOpcode());
          SE->SPOffset = Off;
          SPOffElementMap.insert(std::make_pair(Off, SE));
        } else {
          SE = SPOffElementMap[Off];
        }

        if (SE != nullptr) {
          InstrToElementMap[&MI] = SE;
        }
      }
    }
  }

  // Remove instructions of MOV sp to non-sp.
  for (MachineInstr *MI : RemoveList)
    MI->removeFromParent();

  // TODO: Before generating StackObjects, we need to check whether there is
  // any missed StackElement.

  BasicBlock *EntryBB = &getRaisedFunction()->getEntryBlock();

  assert(EntryBB != nullptr && "There is no BasicBlock in this Function!");
  // Generate StackObjects.
  for (auto StackIter = SPOffElementMap.begin(),
            StackEnd = SPOffElementMap.end();
       StackIter != StackEnd;
       ++StackIter) {
    StackElement *SElm = StackIter->second;
    Align MALG(SElm->Size);
    AllocaInst *Alc =
        new AllocaInst(getStackType(SElm->Size), 0, nullptr, MALG, "", EntryBB);
    int Idx = MFI->CreateStackObject(SElm->Size, Align(4), false, Alc);
    Alc->setName("stack." + std::to_string(Idx));
    MFI->setObjectOffset(Idx, SElm->SPOffset);
    SElm->ObjectIndex = Idx;
  }

  // Replace original SP operands by stack operands.
  for (auto MSIter = InstrToElementMap.begin(), MSEnd = InstrToElementMap.end();
       MSIter != MSEnd; ++MSIter) {
    MachineInstr *MI = MSIter->first;
    StackElement *SE = MSIter->second;
    MI->getOperand(1).ChangeToFrameIndex(SE->ObjectIndex);
    unsigned Opc = MI->getOpcode();
    if (isHalfwordOP(Opc)) {
      MI->removeOperand(3);
    }
    MI->removeOperand(2);
  }

  for (auto &Elm : SPOffElementMap)
    delete Elm.second;
}

bool ARMFrameBuilder::build() {
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder start.\n");

  searchStackObjects(*MF);

  // For debugging.
  LLVM_DEBUG(MF->dump());
  LLVM_DEBUG(getRaisedFunction()->dump());
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder end.\n");

  return true;
}

bool ARMFrameBuilder::runOnMachineFunction(MachineFunction &MF) {
  init();
  return build();
}

#undef DEBUG_TYPE

extern "C" FunctionPass *createARMFrameBuilder(ARMModuleRaiser &MR,
                                               MachineFunction *MF,
                                               Function *RF) {
  return new ARMFrameBuilder(MR, MF, RF);
}
