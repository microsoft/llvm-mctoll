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
  assert(SrcOp.isReg() && "Expected register operand");

  Value *SrcVal = getRegOrArgValue(SrcOp.getReg(), MBBNo);

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

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);
  const MachineOperand &LoadOp = MI.getOperand(MemoryRefOpIndex);
  unsigned int LoadPReg = LoadOp.getReg();
  assert(Register::isPhysicalRegister(LoadPReg) &&
         "Expect destination to be a physical register in SSE conversion "
         "instruction.");

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access), GlobalValue (global
  // data access), an effective address value, element pointer or select
  // instruction.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue) || isa<SelectInst>(MemRefValue) ||
          isa<GetElementPtrInst>(MemRefValue) ||
          MemRefValue->getType()->isPointerTy()) &&
         "Unexpected type of memory reference in SSE conversion instruction");

  // Assume that MemRefValue represents a memory reference location and hence
  // needs to be loaded from.
  bool LoadFromMemrefValue = true;
  // Following are the exceptions when MemRefValue needs to be considered as
  // memory content and not as memory reference.
  if (IsPCRelMemRef) {
    // If it is a PC-relative global variable with an initializer, it is memory
    // content and should not be loaded from.
    if (auto GV = dyn_cast<GlobalVariable>(MemRefValue))
      LoadFromMemrefValue = !(GV->hasInitializer());
    // If it is not a PC-relative constant expression accessed using
    // GetElementPtrInst, it is memory content and should not be loaded from.
    else {
      const ConstantExpr *CExpr = dyn_cast<ConstantExpr>(MemRefValue);
      if (CExpr != nullptr) {
        LoadFromMemrefValue =
            (CExpr->getOpcode() == Instruction::GetElementPtr);
      }
    }
  }

  Value *SrcVal;
  if (LoadFromMemrefValue) {
    // If it is an effective address value or a select instruction, convert it
    // to a pointer to load register type.
    PointerType *PtrTy = PointerType::get(SrcTy, 0);
    if ((isEffectiveAddrValue(MemRefValue)) || isa<SelectInst>(MemRefValue)) {
      IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      // Set or copy rodata metadata, if any
      getRaisedValues()->setInstMetadataRODataIndex(MemRefValue, ConvIntToPtr);
      RaisedBB->getInstList().push_back(ConvIntToPtr);
      MemRefValue = ConvIntToPtr;
    }
    assert(MemRefValue->getType()->isPointerTy() &&
           "Pointer type expected in SSE conversion instruction");
    // Cast the pointer to match the size of memory being accessed by the
    // instruction, as needed.
    MemRefValue = getRaisedValues()->castValue(MemRefValue, PtrTy, RaisedBB);
    // Load the value from memory location
    Type *LdTy = MemRefValue->getType()->getPointerElementType();
    LoadInst *LdInst =
        new LoadInst(LdTy, MemRefValue, "memload", false, Align());
    LdInst = getRaisedValues()->setInstMetadataRODataContent(LdInst);
    RaisedBB->getInstList().push_back(LdInst);

    SrcVal = LdInst;
  } else {
    // memRefValue already represents the global value loaded from
    // PC-relative memory location. It is incorrect to generate an
    // additional load of this value. It should be directly used.
    SrcVal = MemRefValue;
  }

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

  bool Success = true;
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

  switch (MI.getOpcode()) {
  case X86::MOVAPSrr:
  case X86::MOVAPDrr: {
    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
    unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src1Index);

    // Verify sanity of the instruction.
    assert(DstPRegSize != 0 && DstPRegSize == SrcPRegSize &&
           "Unexpected sizes of source and destination registers size differ "
           "in sse mov instruction");
    assert(SrcValue &&
           "Encountered sse mov instruction with undefined source register");
    assert(SrcValue->getType()->isSized() &&
           "Unsized source value in sse mov instruction");
    MachineOperand MO = MI.getOperand(Src1Index);
    assert(MO.isReg() && "Unexpected non-register operand");
    // Check for undefined use
    Success = (SrcValue != nullptr);
    if (Success)
      // Update the value mapping of DstPReg
      raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SrcValue);
  } break;
  default:
    llvm_unreachable("Unhandled sse mov instruction");
  }

  return Success;
}
