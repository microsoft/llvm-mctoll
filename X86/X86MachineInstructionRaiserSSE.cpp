//===-- X86MachineInstructionRaiserSSE.cpp -----------------------*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains implementaion of functions to raise SSE2 instructions
// declared in X86MachineInstructionRaiser class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ExternalFunctions.h"
#include "X86MachineInstructionRaiser.h"
#include "X86RaisedValueTracker.h"
#include "X86RegisterUtils.h"
#include "llvm-mctoll.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <X86InstrBuilder.h>
#include <X86Subtarget.h>
#include <iterator>

using namespace llvm;
using namespace mctoll;
using namespace X86RegisterUtils;

bool X86MachineInstructionRaiser::raiseSSECompareMachineInstr(
    const MachineInstr &MI) {
  const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
  // Ensure this is an SSE2 compare instruction
  int MBBNo = MI.getParent()->getNumber();
  MCInstrDesc MCIDesc = MI.getDesc();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  assert((MCIDesc.getNumDefs() == 0) && (MCIDesc.getNumOperands() == 2) &&
         (MCIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS)) &&
         MCIDesc.hasImplicitUseOfPhysReg(X86::MXCSR) &&
         "Unexpected operands found in SSE compare instruction");
  MachineOperand CmpOp1 = MI.getOperand(0);
  MachineOperand CmpOp2 = MI.getOperand(1);
  assert(CmpOp1.isReg() && CmpOp2.isReg() &&
         "Expected register operands not found in SSE compare instruction");
  Register CmpOpReg1 = CmpOp1.getReg();
  Register CmpOpReg2 = CmpOp2.getReg();
  assert(
      isSSE2Reg(CmpOpReg1) && isSSE2Reg(CmpOpReg2) &&
      "Expected SSE2 register operands not found in SSE compare instruction");
  Value *CmpOpVal1 = getRegOrArgValue(CmpOpReg1, MBBNo);
  Value *CmpOpVal2 = getRegOrArgValue(CmpOpReg2, MBBNo);
  // Initialize EFLAGS; AF and PF are not yet modeled
  raisedValues->setEflagBoolean(EFLAGS::OF, MBBNo, false);
  raisedValues->setEflagBoolean(EFLAGS::SF, MBBNo, false);

  auto CmpOp1SzInBits =
      TRI->getRegSizeInBits(*(TRI->getRegClass(MCIDesc.OpInfo[0].RegClass)));
  auto CmpOp2SzInBits =
      TRI->getRegSizeInBits(*(TRI->getRegClass(MCIDesc.OpInfo[1].RegClass)));
  assert(CmpOp1SzInBits == CmpOp2SzInBits &&
         "Different sizes of SSE compare instruction not expected");
  bool IsUnorderedCompare = false;
  switch (MI.getOpcode()) {
  default:
    break;
  case X86::UCOMISDrr:
  case X86::UCOMISSrr:
    IsUnorderedCompare = true;
    break;
  }
  if (IsUnorderedCompare) {
    // Testing for unordered less-than and unordered equal will set CF and ZF
    // appropriately viz.,
    //     Unordered   :  ZF,CF <- 11
    //     Greater-than:  ZF,CF <= 00
    //     Less-than   :  ZF,CF <= 10
    // Unordered or Less-than
    auto ULTCmp = new FCmpInst(*RaisedBB, CmpInst::Predicate::FCMP_ULT,
                               CmpOpVal1, CmpOpVal2);
    raisedValues->setEflagValue(EFLAGS::CF, MBBNo, ULTCmp);

    // Unordered or Equal
    auto UEQCmp = new FCmpInst(*RaisedBB, CmpInst::Predicate::FCMP_UEQ,
                               CmpOpVal1, CmpOpVal2);
    raisedValues->setEflagValue(EFLAGS::ZF, MBBNo, UEQCmp);

    // Unordered
    auto UNOCmp = new FCmpInst(*RaisedBB, CmpInst::Predicate::FCMP_UNO,
                               CmpOpVal1, CmpOpVal2);
    raisedValues->setEflagValue(EFLAGS::PF, MBBNo, UNOCmp);

  } else {
    llvm_unreachable("Unhandled SSE compare instruction");
  }

  return true;
}

bool X86MachineInstructionRaiser::raiseSSEConvertPrecisionMachineInstr(
    const MachineInstr &MI) {
  int MBBNo = MI.getParent()->getNumber();
  MCInstrDesc MCIDesc = MI.getDesc();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  // Ensure this is an SSE2 compare instruction
  assert((MCIDesc.getNumDefs() == 1) && (MCIDesc.getNumOperands() == 3) &&
         MCIDesc.hasImplicitUseOfPhysReg(X86::MXCSR) &&
         "Unexpected operands found in SSE precision conversion instruction");
  unsigned int DstOpIdx = 0, SrcOp1Idx = 1, SrcOp2Idx = 2;
  MachineOperand DstOp = MI.getOperand(DstOpIdx);
  MachineOperand SrcOp1 = MI.getOperand(SrcOp1Idx);
  MachineOperand SrcOp2 = MI.getOperand(SrcOp2Idx);
  assert(DstOp.isTied() && (MI.findTiedOperandIdx(DstOpIdx) == SrcOp1Idx) &&
         "Expect destination operand to be tied");
  assert(SrcOp1.isReg() && SrcOp2.isReg() &&
         "NYI - SSE precision conversion instructions with memory operands");

  Register SrcOpReg1 = SrcOp1.getReg();
  Register SrcOpReg2 = SrcOp2.getReg();
  assert(
      isSSE2Reg(SrcOpReg1) && isSSE2Reg(SrcOpReg2) &&
      "Expected SSE2 register operands not found in SSE compare instruction");
  Value *SrcVal = getRegOrArgValue(SrcOpReg2, MBBNo);

  LLVMContext &Ctx(MF.getFunction().getContext());
  CastInst *CastToInst;

  if (SrcVal->getType()->isFloatTy()) {
    // Cast float type to double.
    Type *CastTy = Type::getDoubleTy(Ctx);
    CastToInst =
        CastInst::Create(CastInst::getCastOpcode(SrcVal, false, CastTy, false),
                         SrcVal, CastTy, "ss2sd", RaisedBB);
  } else if (SrcVal->getType()->isDoubleTy()) {
    // Cast double type to float.
    Type *CastTy = Type::getFloatTy(Ctx);
    CastToInst =
        CastInst::Create(CastInst::getCastOpcode(SrcVal, false, CastTy, false),
                         SrcVal, CastTy, "sd2ss", RaisedBB);
  } else {
    llvm_unreachable("Unexpected non-float typed value while raising SSE "
                     "precision conversion instruction");
  }

  raisedValues->setPhysRegSSAValue(DstOp.getReg(),
                                   MI.getParent()->getNumber(), CastToInst);

  return true;
}
