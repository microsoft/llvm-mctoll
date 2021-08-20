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
  assert((MCIDesc.getNumDefs() == 0 || MCIDesc.getNumDefs() == 1) &&
         (MCIDesc.getNumOperands() == 2 || MCIDesc.getNumOperands() == 4) &&
         "Unexpected operands found in SSE compare instruction");

  unsigned int Src1Idx, Src2Idx;

  if (MCIDesc.getNumOperands() == 2) {
    Src1Idx = 0;
    Src2Idx = 1;
  } else if (MCIDesc.getNumOperands() == 4) {
    Src1Idx = 1;
    Src2Idx = 2;
  } else {
    llvm_unreachable("Unexpected operands found in SSE compare instruction");
  }

  MachineOperand CmpOp1 = MI.getOperand(Src1Idx);
  MachineOperand CmpOp2 = MI.getOperand(Src2Idx);

  assert(CmpOp1.isReg() && CmpOp2.isReg() &&
         "Expected register operands not found in SSE compare instruction");
  Register CmpOpReg1 = CmpOp1.getReg();
  Register CmpOpReg2 = CmpOp2.getReg();
  assert(
      isSSE2Reg(CmpOpReg1) && isSSE2Reg(CmpOpReg2) &&
      "Expected SSE2 register operands not found in SSE compare instruction");
  Value *CmpOpVal1 = getRegOrArgValue(CmpOpReg1, MBBNo);
  Value *CmpOpVal2 = getRegOrArgValue(CmpOpReg2, MBBNo);

  auto CmpOp1SzInBits =
      TRI->getRegSizeInBits(*(TRI->getRegClass(MCIDesc.OpInfo[0].RegClass)));
  auto CmpOp2SzInBits =
      TRI->getRegSizeInBits(*(TRI->getRegClass(MCIDesc.OpInfo[1].RegClass)));
  assert(CmpOp1SzInBits == CmpOp2SzInBits &&
         "Different sizes of SSE compare instruction not expected");

  LLVMContext &Ctx(MF.getFunction().getContext());

  Type *OpType = getRaisedValues()->getSSEInstructionType(MI, Ctx);

  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  CmpOpVal1 = getRaisedValues()->reinterpretSSERegValue(CmpOpVal1, OpType, RaisedBB);
  CmpOpVal2 = getRaisedValues()->reinterpretSSERegValue(CmpOpVal2, OpType, RaisedBB);

  return raiseSSECompareMachineInstr(MI, CmpOpVal1, CmpOpVal2, false);
}

bool X86MachineInstructionRaiser::raiseSSECompareFromMemMachineInstr(
    const MachineInstr &MI, Value *MemRefValue) {
  LLVMContext &Ctx(MF.getFunction().getContext());
  // Ensure this is an SSE2 compare instruction
  int MBBNo = MI.getParent()->getNumber();
  MCInstrDesc MCIDesc = MI.getDesc();

  assert((MCIDesc.getNumDefs() == 0 || MCIDesc.getNumDefs() == 1) &&
         "Unexpected operands found in SSE compare instruction");

  unsigned int Src1Idx;

  if (MCIDesc.getNumDefs() == 0) {
    Src1Idx = 0;
  } else if (MCIDesc.getNumDefs() == 1) {
    Src1Idx = 1;
  } else {
    llvm_unreachable("Unexpected operands found in SSE compare instruction");
  }

  MachineOperand CmpOp1 = MI.getOperand(Src1Idx);
  assert(CmpOp1.isReg() &&
         "Expected register operand not found in SSE compare instruction");
  Register CmpOpReg1 = CmpOp1.getReg();
  assert(isSSE2Reg(CmpOpReg1) &&
         "Expected SSE2 register operand not found in SSE compare instruction");

  unsigned int MemoryRefOpIndex = getMemoryRefOpIndex(MI);

  Type *OpType = getRaisedValues()->getSSEInstructionType(MI, Ctx);

  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  Value *CmpOpVal1 = getRaisedValues()->reinterpretSSERegValue(
      getRegOrArgValue(CmpOpReg1, MBBNo), OpType, RaisedBB);
  Value *CmpOpVal2 =
      loadMemoryRefValue(MI, MemRefValue, MemoryRefOpIndex, OpType);

  return raiseSSECompareMachineInstr(MI, CmpOpVal1, CmpOpVal2, true);
}

bool X86MachineInstructionRaiser::raiseSSECompareMachineInstr(
    const MachineInstr &MI, Value *CmpOpVal1, Value *CmpOpVal2,
    bool IsFromMem) {
  LLVMContext &Ctx(MF.getFunction().getContext());
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  int MBBNo = MI.getParent()->getNumber();
  MCInstrDesc MCIDesc = MI.getDesc();

  switch (MI.getOpcode()) {
  case X86::UCOMISDrr:
  case X86::UCOMISSrr:
  case X86::UCOMISDrm:
  case X86::UCOMISSrm: {
    // Testing for unordered less-than and unordered equal will set ZF, PF and
    // CF appropriately viz.,
    //    Unordered:    ZF,PF,CF <- 111
    //    Greater-than: ZF,PF,CF <- 000
    //    Less-than:    ZF,PF,CF <- 001
    //    equal:        ZF,PF,CF <- 100
    assert(MCIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           MCIDesc.hasImplicitUseOfPhysReg(X86::MXCSR) &&
           "Unexpected operands found in SSE compare instruction");

    assert(CmpOpVal1->getType()->isVectorTy() &&
           CmpOpVal2->getType()->isVectorTy() &&
           "Expected operand types to be vector types");

    auto Idx = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
    CmpOpVal1 =
        ExtractElementInst::Create(CmpOpVal1, Idx, "cmp_operand_1", RaisedBB);
    CmpOpVal2 =
        ExtractElementInst::Create(CmpOpVal2, Idx, "cmp_operand_2", RaisedBB);

    assert(CmpOpVal1->getType()->isFloatingPointTy() &&
           CmpOpVal2->getType()->isFloatingPointTy() &&
           "Expected operand types to be of floating point type for SSE "
           "compare instruction");

    // Initialize EFLAGS; AF and PF are not yet modeled
    raisedValues->setEflagBoolean(EFLAGS::OF, MBBNo, false);
    raisedValues->setEflagBoolean(EFLAGS::SF, MBBNo, false);

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
  } break;
  case X86::CMPSDrr_Int:
  case X86::CMPSSrr_Int:
  case X86::CMPSDrm_Int:
  case X86::CMPSSrm_Int: {
    // Testing if two values are equal will set destination register to
    // all-1 or all-0 depending on if they are equal
    LLVMContext &Ctx(MF.getFunction().getContext());
    MachineOperand DstOp = MI.getOperand(0);
    assert(DstOp.isReg() && "Expected destination operand to be a register");
    Register DstReg = DstOp.getReg();

    unsigned int CmpOpTypeIdx = IsFromMem ? 7 : 3;
    MachineOperand CmpTypeOperand = MI.getOperand(CmpOpTypeIdx);
    assert(CmpTypeOperand.isImm() &&
           "Expected comparison type to be immediate");

    assert(CmpOpVal1->getType()->isFloatingPointTy() &&
           CmpOpVal2->getType()->isFloatingPointTy() &&
           "Expected operand types to be of floating point type for SSE "
           "compare instruction");

    Instruction *CmpInst;
    // Different types of compare instruction:
    // https://www.felixcloutier.com/x86/cmpsd
    switch (CmpTypeOperand.getImm()) {
    case 0: // CMPEQSD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_OEQ, CmpOpVal1, CmpOpVal2,
                             "CMPEQ");
      break;
    case 1: // CMPLTSD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_OLT, CmpOpVal1, CmpOpVal2,
                             "CMPLT");
      break;
    case 2: // CMPLESD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_OLE, CmpOpVal1, CmpOpVal2,
                             "CMPLE");
      break;
    case 3: // CMPUNORDSD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_UNO, CmpOpVal1, CmpOpVal2,
                             "CMPUNORD");
      break;
    case 4: // CMPNEQSD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_ONE, CmpOpVal1, CmpOpVal2,
                             "CMPNEQ");
      break;
    case 5: { // CMPNLTSD
      auto LTInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_OLT, CmpOpVal1,
                                 CmpOpVal2, "CMPLT");
      CmpInst = BinaryOperator::CreateNot(LTInst, "CMPNLT", RaisedBB);
    } break;
    case 6: { // CMPNLESD
      auto LEInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_OLE, CmpOpVal1,
                                 CmpOpVal2, "CMPLE");
      CmpInst = BinaryOperator::CreateNot(LEInst, "CMPNLE", RaisedBB);
    } break;
    case 7: // CMPORDSD
      CmpInst = new FCmpInst(*RaisedBB, CmpInst::FCMP_ORD, CmpOpVal1, CmpOpVal2,
                             "CMPORD");
      break;
    default:
      llvm_unreachable(
          "Encountered illegal comparison type in comparison instruction");
    }

    unsigned int BitSize = CmpOpVal1->getType()->getPrimitiveSizeInBits();
    IntegerType *IntNTy = Type::getIntNTy(Ctx, BitSize);

    Value *BitmaskInt = ConstantInt::get(IntNTy, IntNTy->getBitMask());
    Value *ZeroValInt = ConstantInt::get(IntNTy, 0);

    Value *BitmaskVal =
        new BitCastInst(BitmaskInt, CmpOpVal1->getType(), "bitmask", RaisedBB);
    Value *ZeroVal =
        new BitCastInst(ZeroValInt, CmpOpVal1->getType(), "zero", RaisedBB);

    Instruction *SelectInstr = SelectInst::Create(CmpInst, BitmaskVal, ZeroVal,
                                                  "cmp_bitmask", RaisedBB);
    raisedValues->setPhysRegSSAValue(DstReg, MI.getParent()->getNumber(),
                                     SelectInstr);
  } break;
  default:
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
  assert((MCIDesc.getNumDefs() == 1) &&
         "Expected one definition in SSE conversion instruction");
  unsigned int DstOpIdx = 0;
  MachineOperand DstOp = MI.getOperand(DstOpIdx);

  // Find the correct SrcOpIndex for the given instruction
  unsigned SrcOpIdx;
  if (MI.getNumExplicitOperands() == 3) {
    SrcOpIdx = 2;
  } else if (MI.getNumExplicitOperands() == 2) {
    SrcOpIdx = 1;
  } else {
    llvm_unreachable("Unexpected number of explicit operands for SSE convert "
                     "instruction");
  }

  MachineOperand SrcOp = MI.getOperand(SrcOpIdx);
  assert(SrcOp.isReg() && DstOp.isReg() && "Expected register operand");

  LLVMContext &Ctx(MF.getFunction().getContext());

  Type *CastTy;
  switch (MI.getOpcode()) {
  case X86::CVTSD2SIrr_Int:
  case X86::CVTSS2SIrr_Int:
  case X86::CVTTSD2SIrr:
  case X86::CVTTSD2SIrr_Int:
  case X86::CVTTSS2SIrr:
  case X86::CVTTSS2SIrr_Int:
    CastTy = Type::getInt32Ty(Ctx);
    break;
  case X86::CVTSD2SI64rr_Int:
  case X86::CVTSS2SI64rr_Int:
  case X86::CVTTSD2SI64rr:
  case X86::CVTTSD2SI64rr_Int:
  case X86::CVTTSS2SI64rr:
  case X86::CVTTSS2SI64rr_Int:
    CastTy = Type::getInt64Ty(Ctx);
    break;
  case X86::CVTSD2SSrr:
  case X86::CVTSD2SSrr_Int:
  case X86::CVTSI2SSrr:
  case X86::CVTSI2SSrr_Int:
  case X86::CVTSI642SSrr:
  case X86::CVTSI642SSrr_Int:
    CastTy = Type::getFloatTy(Ctx);
    break;
  case X86::CVTSI2SDrr:
  case X86::CVTSI2SDrr_Int:
  case X86::CVTSI642SDrr:
  case X86::CVTSI642SDrr_Int:
  case X86::CVTSS2SDrr:
  case X86::CVTSS2SDrr_Int:
    CastTy = Type::getDoubleTy(Ctx);
    break;
  default:
    MI.dump();
    llvm_unreachable("Unhandled sse convert instruction");
  }

  Value *SrcVal = getRegOrArgValue(SrcOp.getReg(), MBBNo);

  if (isSSE2Reg(SrcOp.getReg())) {
    // re-interpret value as expected source value
    Type *SrcTy = getRaisedValues()->getSSEInstructionType(MI, Ctx);
    SrcVal = getRaisedValues()->reinterpretSSERegValue(SrcVal, SrcTy, RaisedBB);
  }

  auto CastToInst =
      CastInst::Create(CastInst::getCastOpcode(SrcVal, true, CastTy, true),
                       SrcVal, CastTy, "cvt", RaisedBB);

  raisedValues->setPhysRegSSAValue(DstOp.getReg(), MI.getParent()->getNumber(),
                                   CastToInst);

  return true;
}

bool X86MachineInstructionRaiser::raiseSSEConvertPrecisionFromMemMachineInstr(
    const MachineInstr &MI, Value *MemRefValue) {
  LLVMContext &Ctx(MF.getFunction().getContext());
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  Type *CastTy;
  Type *SrcTy;
  switch (MI.getOpcode()) {
  case X86::CVTSD2SIrm_Int:
  case X86::CVTSS2SIrm_Int:
  case X86::CVTTSD2SIrm:
  case X86::CVTTSD2SIrm_Int:
  case X86::CVTTSS2SIrm:
  case X86::CVTTSS2SIrm_Int:
    CastTy = Type::getInt32Ty(Ctx);
    break;
  case X86::CVTSD2SI64rm_Int:
  case X86::CVTSS2SI64rm_Int:
  case X86::CVTTSD2SI64rm:
  case X86::CVTTSD2SI64rm_Int:
  case X86::CVTTSS2SI64rm:
  case X86::CVTTSS2SI64rm_Int:
    CastTy = Type::getInt64Ty(Ctx);
    break;
  case X86::CVTSD2SSrm:
  case X86::CVTSD2SSrm_Int:
  case X86::CVTSI2SSrm:
  case X86::CVTSI2SSrm_Int:
  case X86::CVTSI642SSrm:
  case X86::CVTSI642SSrm_Int:
    CastTy = Type::getFloatTy(Ctx);
    break;
  case X86::CVTSI2SDrm:
  case X86::CVTSI2SDrm_Int:
  case X86::CVTSI642SDrm:
  case X86::CVTSI642SDrm_Int:
  case X86::CVTSS2SDrm:
  case X86::CVTSS2SDrm_Int:
    CastTy = Type::getDoubleTy(Ctx);
    break;
  }
  // Need to figure out the source type, since we don't know that
  // just from the MemoryRefValue
  switch (MI.getOpcode()) {
  case X86::CVTSD2SIrm_Int:
  case X86::CVTSD2SI64rm_Int:
  case X86::CVTSD2SSrm:
  case X86::CVTSD2SSrm_Int:
  case X86::CVTTSD2SIrm:
  case X86::CVTTSD2SIrm_Int:
  case X86::CVTTSD2SI64rm:
  case X86::CVTTSD2SI64rm_Int:
    SrcTy = Type::getDoubleTy(Ctx);
    break;
  case X86::CVTSS2SIrm_Int:
  case X86::CVTTSS2SIrm:
  case X86::CVTTSS2SIrm_Int:
  case X86::CVTSS2SI64rm_Int:
  case X86::CVTTSS2SI64rm:
  case X86::CVTTSS2SI64rm_Int:
  case X86::CVTSS2SDrm:
  case X86::CVTSS2SDrm_Int:
    SrcTy = Type::getFloatTy(Ctx);
    break;
  case X86::CVTSI642SSrm:
  case X86::CVTSI642SSrm_Int:
  case X86::CVTSI642SDrm:
  case X86::CVTSI642SDrm_Int:
    SrcTy = Type::getInt64Ty(Ctx);
    break;
  case X86::CVTSI2SSrm:
  case X86::CVTSI2SSrm_Int:
  case X86::CVTSI2SDrm:
  case X86::CVTSI2SDrm_Int:
    SrcTy = Type::getInt32Ty(Ctx);
    break;
  }
  assert(SrcTy != nullptr && CastTy != nullptr &&
         "Unhandled sse conversion instruction");

  MCInstrDesc MCIDesc = MI.getDesc();

  unsigned int DstOpIdx = 0, MemoryRefOpIndex = getMemoryRefOpIndex(MI);

  assert(MCIDesc.getNumDefs() == 1 &&
         "Unexpected defs found in SSE conversion instruction");

  MachineOperand DstOp = MI.getOperand(DstOpIdx);
  assert(DstOp.isReg() && "Expected destination to be a register");

  Value *SrcVal = loadMemoryRefValue(MI, MemRefValue, MemoryRefOpIndex, SrcTy);

  auto CastInst =
      CastInst::Create(CastInst::getCastOpcode(SrcVal, true, CastTy, true),
                       SrcVal, CastTy, "cvt", RaisedBB);
  raisedValues->setPhysRegSSAValue(DstOp.getReg(), MI.getParent()->getNumber(),
                                   CastInst);

  return true;
}

bool X86MachineInstructionRaiser::raiseSSEMoveRegToRegMachineInstr(
    const MachineInstr &MI) {
  int MBBNo = MI.getParent()->getNumber();
  LLVMContext &Ctx(MF.getFunction().getContext());
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  unsigned DstIndex = 0, Src1Index = 1, Src2Index = 2;
  assert(
      (MI.getNumExplicitOperands() == 2 || MI.getNumExplicitOperands() == 4) &&
      MI.getOperand(DstIndex).isReg() &&
      (MI.getOperand(Src1Index).isReg() || MI.getOperand(Src2Index).isReg()) &&
      "Expecting exactly two operands for sse move reg-to-reg "
      "instructions");

  unsigned int DstPReg = MI.getOperand(DstIndex).getReg();

  // Get source operand value
  Value *SrcValue;
  if (MI.getNumExplicitOperands() == 2) {
    // don't use getRegOperandValue, as we don't want to cast the value
    const MachineOperand &MO = MI.getOperand(Src1Index);
    assert(MO.isReg() && "Register operand expected");
    SrcValue = getRegOrArgValue(MO.getReg(), MI.getParent()->getNumber());
  } else {
    llvm_unreachable(
        "Unexpected operand numbers for sse move reg-to-reg instruction");
  }

  unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
  unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src1Index);

  // Verify sanity of the instruction.
  assert(SrcValue &&
         "Encountered sse mov instruction with undefined source register");
  assert(SrcValue->getType()->isSized() &&
         "Unsized source value in sse mov instruction");
  MachineOperand MO = MI.getOperand(Src1Index);
  assert(MO.isReg() && "Unexpected non-register operand");

  switch (MI.getOpcode()) {
  case X86::MOVAPSrr:
  case X86::MOVAPDrr: {
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SrcValue);
  } break;
  case X86::MOV64toPQIrr:
  case X86::MOVDI2PDIrr:
  case X86::MOVPDI2DIrr:
  case X86::MOVPQIto64rr: {
    Type *DstType;
    if (isSSE2Reg(DstPReg)) {
      // Since for SSE2 registers, DstPRegSize will always be 128, look at
      // SrcPRegSize to get type
      switch (SrcPRegSize * 8) {
      case 32:
        DstType = Type::getFloatTy(Ctx);
        break;
      case 64:
        DstType = Type::getDoubleTy(Ctx);
        break;
      default:
        llvm_unreachable("Unhandled fp size");
      }
    } else {
      DstType = Type::getIntNTy(Ctx, DstPRegSize * 8);
    }

    SrcValue = getRaisedValues()->reinterpretSSERegValue(SrcValue, DstType, RaisedBB);
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SrcValue);
  } break;
  default:
    llvm_unreachable("Unhandled sse mov instruction");
  }

  return true;
}
