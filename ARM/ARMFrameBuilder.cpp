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

char ARMFrameBuilder::ID = 0;

ARMFrameBuilder::ARMFrameBuilder(ARMModuleRaiser &mr) : ARMRaiserBase(ID, mr) {}

ARMFrameBuilder::~ARMFrameBuilder() {}

void ARMFrameBuilder::init(MachineFunction *mf, Function *rf) {
  ARMRaiserBase::init(mf, rf);
  MFI = &MF->getFrameInfo();
  CTX = &M->getContext();
  DLT = &M->getDataLayout();
}

static bool isLoadOP(unsigned opcode) {
  switch (opcode) {
  default:
    return false;
  case ARM::LDRi12:
  case ARM::LDRH:
  case ARM::LDRSH:
  case ARM::LDRBi12:
    return true;
  }
}

static bool isStoreOP(unsigned opcode) {
  switch (opcode) {
  default:
    return false;
  case ARM::STRi12:
  case ARM::STRH:
  case ARM::STRBi12:
    return true;
  }
}

static bool isAddOP(unsigned opcode) {
  switch (opcode) {
  default:
    return false;
  case ARM::ADDri:
    return true;
  }
}

static inline bool isHalfwordOP(unsigned Opcode) {
  bool Res = false;
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

unsigned ARMFrameBuilder::getBitCount(unsigned opcode) {
  unsigned ret;

  switch (opcode) {
  default:
    ret = Log2(DLT->getStackAlignment());
    break;
  case ARM::LDRi12:
  case ARM::STRi12:
    ret = 4;
    break;
  case ARM::LDRBi12:
  case ARM::STRBi12:
    ret = 1;
    break;
  case ARM::STRH:
  case ARM::LDRH:
  case ARM::LDRSH:
    ret = 2;
    break;
  case ARM::ADDri:
    ret = 4;
    break;
  }

  return ret;
}

Type *ARMFrameBuilder::getStackType(unsigned size) {
  Type *t = nullptr;

  switch (size) {
  default:
    t = Type::getIntNTy(M->getContext(),
                        M->getDataLayout().getPointerSizeInBits());
    break;
  case 8:
    t = Type::getInt64Ty(*CTX);
    break;
  case 4:
    t = Type::getInt32Ty(*CTX);
    break;
  case 2:
    t = Type::getInt16Ty(*CTX);
    break;
  case 1:
    t = Type::getInt8Ty(*CTX);
    break;
  }

  return t;
}

/// Replace common regs assigned by SP to SP.
/// Patterns like:
/// mov r5, sp
/// ldr r3, [r5, #4]
/// In this case, r5 should be replace by sp.
bool ARMFrameBuilder::replaceNonSPBySP(MachineInstr &mi) {
  if (mi.getOpcode() == ARM::MOVr) {
    if (mi.getOperand(1).isReg() && mi.getOperand(1).getReg() == ARM::SP) {
      if (mi.getOperand(0).isReg() && mi.getOperand(0).isDef()) {
        RegAssignedBySP.push_back(mi.getOperand(0).getReg());
        return true;
      }
    }
  }

  // Replace regs which are assigned by sp.
  for (MachineOperand &mo : mi.uses()) {
    for (unsigned odx : RegAssignedBySP) {
      if (mo.isReg() && mo.getReg() == odx) {
        mo.ChangeToRegister(ARM::SP, false);
      }
    }
  }

  // Record regs which are assigned by sp.
  for (MachineOperand &mo : mi.defs()) {
    for (SmallVector<unsigned, 16>::iterator I = RegAssignedBySP.begin();
         I != RegAssignedBySP.end();) {
      if (mo.isReg() && mo.getReg() == *I) {
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
int64_t ARMFrameBuilder::identifyStackOp(const MachineInstr &mi) {
  unsigned opc = mi.getOpcode();
  if (!isLoadOP(opc) && !isStoreOP(opc) && !isAddOP(opc))
    return -1;

  if (mi.getNumOperands() < 3)
    return -1;

  int64_t offset = -1;
  const MachineOperand &mo = mi.getOperand(1);

  if (!mo.isReg())
    return -1;

  if (isHalfwordOP(opc))
    offset = mi.getOperand(3).getImm();
  else
    offset = mi.getOperand(2).getImm();

  if (mo.getReg() == ARM::SP && offset >= 0)
    return offset;

  if (mo.getReg() == ARM::R11) {
    if (offset > 0) {
      if (isHalfwordOP(opc))
        offset = 0 - static_cast<int64_t>(static_cast<int8_t>(offset));
      else
        return -1;
    }
    return MFI->getStackSize() + offset + MFI->getOffsetAdjustment();
  }

  return -1;
}

/// Find out all of frame relative operands, and update them.
void ARMFrameBuilder::searchStackObjects(MachineFunction &mf) {
  // <SPOffset, frame_element_ptr>
  std::map<int64_t, StackElement *, std::greater<int64_t>> SPOffElementMap;
  DenseMap<MachineInstr *, StackElement *> InstrToElementMap;

  std::vector<MachineInstr *> removelist;
  for (MachineFunction::iterator mbbi = mf.begin(), mbbe = mf.end();
       mbbi != mbbe; ++mbbi) {
    for (MachineBasicBlock::iterator mii = mbbi->begin(), mie = mbbi->end();
         mii != mie; ++mii) {
      MachineInstr &mi = *mii;

      if (replaceNonSPBySP(mi)) {
        removelist.push_back(&mi);
        continue;
      }

      int64_t off = identifyStackOp(mi);
      if (off >= 0) {
        StackElement *se = nullptr;
        if (SPOffElementMap.count(off) == 0) {
          se = new StackElement();
          se->Size = getBitCount(mi.getOpcode());
          se->SPOffset = off;
          SPOffElementMap.insert(std::make_pair(off, se));
        } else {
          se = SPOffElementMap[off];
        }

        if (se != nullptr) {
          InstrToElementMap[&mi] = se;
        }
      }
    }
  }

  // Remove instructions of MOV sp to non-sp.
  for (MachineInstr *mi : removelist)
    mi->removeFromParent();

  // TODO: Before generating StackObjects, we need to check whether there is
  // any missed StackElement.

  BasicBlock *pBB = &getCRF()->getEntryBlock();

  assert(pBB != nullptr && "There is no BasicBlock in this Function!");
  // Generate StackObjects.
  for (auto ii = SPOffElementMap.begin(), ie = SPOffElementMap.end(); ii != ie;
       ++ii) {
    StackElement *sem = ii->second;
    Align MALG(sem->Size);
    AllocaInst *alc =
        new AllocaInst(getStackType(sem->Size), 0, nullptr, MALG, "", pBB);
    int idx = MFI->CreateStackObject(sem->Size, Align(4), false, alc);
    alc->setName("stack." + std::to_string(idx));
    MFI->setObjectOffset(idx, sem->SPOffset);
    sem->ObjectIndex = idx;
  }

  // Replace original SP operands by stack operands.
  for (auto msi = InstrToElementMap.begin(), mse = InstrToElementMap.end();
       msi != mse; ++msi) {
    MachineInstr *pmi = msi->first;
    StackElement *pse = msi->second;
    pmi->getOperand(1).ChangeToFrameIndex(pse->ObjectIndex);
    unsigned opc = pmi->getOpcode();
    if (isHalfwordOP(opc)) {
      pmi->removeOperand(3);
    }
    pmi->removeOperand(2);
  }

  for (auto &e : SPOffElementMap)
    delete e.second;
}

bool ARMFrameBuilder::build() {
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder start.\n");

  searchStackObjects(*MF);

  // For debugging.
  LLVM_DEBUG(MF->dump());
  LLVM_DEBUG(getCRF()->dump());
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder end.\n");

  return true;
}

bool ARMFrameBuilder::runOnMachineFunction(MachineFunction &mf) {
  bool rtn = false;
  init();
  rtn = build();
  return rtn;
}

#undef DEBUG_TYPE

#ifdef __cplusplus
extern "C" {
#endif

FunctionPass *InitializeARMFrameBuilder(ARMModuleRaiser &mr) {
  return new ARMFrameBuilder(mr);
}

#ifdef __cplusplus
}
#endif
