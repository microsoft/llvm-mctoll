//===-- X86MachineInstructionRaiser.cpp -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of X86MachineInstructionRaiser class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "X86MachineInstructionRaiser.h"
#include "ExternalFunctions.h"
#include "MachineFunctionRaiser.h"
#include "X86InstrBuilder.h"
#include "X86ModuleRaiser.h"
#include "X86RaisedValueTracker.h"
#include "X86RegisterUtils.h"
#include "llvm-mctoll.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/LoopTraversal.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <X86InstrBuilder.h>
#include <X86Subtarget.h>
#include <set>
#include <vector>
using namespace llvm;
using namespace mctoll;
using namespace X86RegisterUtils;

// Constructor

X86MachineInstructionRaiser::X86MachineInstructionRaiser(MachineFunction &MF,
                                                         const ModuleRaiser *MR,
                                                         MCInstRaiser *MIR)
    : MachineInstructionRaiser(MF, MR, MIR), machineRegInfo(MF.getRegInfo()),
      x86TargetInfo(MF.getSubtarget<X86Subtarget>()) {
  x86InstrInfo = x86TargetInfo.getInstrInfo();
  x86RegisterInfo = x86TargetInfo.getRegisterInfo();
  PrintPass =
      (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() > 0);

  FPUStack.TOP = 0;
  for (int i = 0; i < FPUSTACK_SZ; i++)
    FPUStack.Regs[i] = nullptr;

  raisedValues = nullptr;
}

bool X86MachineInstructionRaiser::raisePushInstruction(const MachineInstr &mi) {
  const MCInstrDesc &MCIDesc = mi.getDesc();
  uint64_t MCIDTSFlags = MCIDesc.TSFlags;

  if ((MCIDTSFlags & X86II::FormMask) == X86II::AddRegFrm) {
    // This is a register PUSH. If the source is register, create a slot on
    // the stack.
    if (mi.getOperand(0).isReg()) {
      const DataLayout &DL = MR->getModule()->getDataLayout();
      unsigned AllocaAddrSpace = DL.getAllocaAddrSpace();

      // Create alloca instruction to allocate stack slot
      Type *Ty = getPhysRegOperandType(mi, 0);
      AllocaInst *Alloca =
          new AllocaInst(Ty, AllocaAddrSpace, 0, DL.getPrefTypeAlignment(Ty));

      // Create a stack slot associated with the alloca instruction
      unsigned int StackFrameIndex = MF.getFrameInfo().CreateStackObject(
          (Ty->getPrimitiveSizeInBits() / 8), DL.getPrefTypeAlignment(Ty),
          false /* isSpillSlot */, Alloca);

      // Compute size of new stack object.
      const MachineFrameInfo &MFI = MF.getFrameInfo();
      // Size of currently allocated object size
      int64_t ObjectSize = MFI.getObjectSize(StackFrameIndex);

      // Get the offset of the top of stack. Note that stack objects in MFI are
      // not sorted by offset. So we need to walk the stack objects to find the
      // offset of the top stack object.
      int64_t StackTopOffset = 0;
      for (int StackIndex = MFI.getObjectIndexBegin();
           StackIndex < MFI.getObjectIndexEnd(); StackIndex++) {
        int64_t ObjOffset = MFI.getObjectOffset(StackIndex);
        if (ObjOffset < StackTopOffset)
          StackTopOffset = ObjOffset;
      }
      int64_t Offset = StackTopOffset - ObjectSize;
      // Set object size.
      MF.getFrameInfo().setObjectOffset(StackFrameIndex, Offset);

      // Add the alloca instruction to entry block
      insertAllocaInEntryBlock(Alloca);
      // The alloca corresponds to the current location of stack pointer
      raisedValues->setPhysRegSSAValue(X86::RSP, mi.getParent()->getNumber(),
                                       Alloca);
      return true;
    } else {
      assert(false && "Unhandled PUSH instruction with a non-register operand");
    }
  } else {
    assert(false && "Unhandled PUSH instruction with source operand other "
                    "than AddrRegFrm");
  }
  return false;
}

bool X86MachineInstructionRaiser::raisePopInstruction(const MachineInstr &mi) {
  // TODO : Need to handle pop instructions other than those that restore bp
  // from stack.
  const MCInstrDesc &MCIDesc = mi.getDesc();
  uint64_t MCIDTSFlags = MCIDesc.TSFlags;

  if ((MCIDTSFlags & X86II::FormMask) == X86II::AddRegFrm) {
    // This is a register POP. If the source is base pointer,
    // not need to raise the instruction.
    if (mi.definesRegister(X86::RBP) || mi.definesRegister(X86::EBP)) {
      return true;
    } else {
      // assert(false && "Unhandled POP instruction that restores a register
      // "
      //                "other than frame pointer");
      return true;
    }
  } else {
    if (getInstructionKind(mi.getOpcode()) == InstructionKind::LEAVE_OP) {
      return true;
    }
    assert(false && "Unhandled POP instruction with source operand other "
                    "than AddrRegFrm");
  }
  return false;
}

bool X86MachineInstructionRaiser::raiseConvertBWWDDQMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();
  LLVMContext &llvmContext(MF.getFunction().getContext());

  assert(MIDesc.getNumImplicitUses() == 1 && MIDesc.getNumImplicitDefs() == 1 &&
         "Unexpected number of implicit uses and defs in cbw/cwde/cdqe "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  MCPhysReg UseReg = MIDesc.ImplicitUses[0];
  MCPhysReg DefReg = MIDesc.ImplicitDefs[0];
  Type *TargetTy = nullptr;

  if (Opcode == X86::CDQE) {
    assert(is32BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cdqe instruction");
    assert(is64BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cdqe instruction");
    TargetTy = Type::getInt64Ty(llvmContext);
  } else if (Opcode == X86::CBW) {
    assert(is8BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cbw instruction");
    assert(is16BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cbw instruction");
    TargetTy = Type::getInt16Ty(llvmContext);
  } else if (Opcode == X86::CWDE) {
    assert(is16BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cwde instruction");
    assert(is32BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cwde instruction");
    TargetTy = Type::getInt32Ty(llvmContext);
  }
  assert(TargetTy != nullptr &&
         "Target type not set for cbw/cwde/cdqe instruction");
  Value *UseValue = getRegOperandValue(
      MI, MI.findRegisterUseOperandIdx(UseReg, false, nullptr));

  // Generate sign-extend instruction
  SExtInst *SextInst = new SExtInst(UseValue, TargetTy);
  RaisedBB->getInstList().push_back(SextInst);

  // Update the value mapping of DefReg
  raisedValues->setPhysRegSSAValue(DefReg, MI.getParent()->getNumber(),
                                   SextInst);
  return true;
}

bool X86MachineInstructionRaiser::raiseConvertWDDQQOMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();
  LLVMContext &Ctx(MF.getFunction().getContext());

  assert(MIDesc.getNumImplicitUses() == 1 && MIDesc.getNumImplicitDefs() == 2 &&
         "Unexpected number of implicit uses and defs in cwd/cdq/cqo "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  MCPhysReg UseReg = MIDesc.ImplicitUses[0];
  MCPhysReg DefReg_0 = MIDesc.ImplicitDefs[0];
  MCPhysReg DefReg_1 = MIDesc.ImplicitDefs[1];
  Type *TargetTy = nullptr;
  Type *UseRegTy = nullptr;

  if (Opcode == X86::CWD) {
    assert(is16BitPhysReg(UseReg) && is16BitPhysReg(DefReg_0) &&
           is16BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cwd "
           "instruction");
    TargetTy = Type::getInt32Ty(Ctx);
    UseRegTy = Type::getInt16Ty(Ctx);
  } else if (Opcode == X86::CDQ) {
    assert(is32BitPhysReg(UseReg) && is32BitPhysReg(DefReg_0) &&
           is32BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cdq "
           "instruction");
    TargetTy = Type::getInt64Ty(Ctx);
    UseRegTy = Type::getInt32Ty(Ctx);
  } else if (Opcode == X86::CQO) {
    assert(is64BitPhysReg(UseReg) && is16BitPhysReg(DefReg_0) &&
           is64BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cdo "
           "instruction");
    TargetTy = Type::getInt128Ty(Ctx);
    UseRegTy = Type::getInt64Ty(Ctx);
  }

  assert((TargetTy != nullptr) && (UseRegTy != nullptr) &&
         "Target type not set for cwd/cdq/cqo instruction");
  Value *UseValue = getRegOrArgValue(UseReg, MI.getParent()->getNumber());

  // Generate sign-extend instruction
  SExtInst *TargetSextInst = new SExtInst(UseValue, TargetTy);
  assert(UseValue->getType()->getScalarSizeInBits() ==
             UseRegTy->getScalarSizeInBits() &&
         "Mismatched types in cwd/cdq/cqo instruction");
  RaisedBB->getInstList().push_back(TargetSextInst);

  // Logical Shift TargetSextInst by n-bits (where n is the size of
  // UserRegTy) to get the high bytes and set DefReg_1 to the resulting
  // value.
  Value *ShiftAmount = ConstantInt::get(
      TargetTy, UseRegTy->getScalarSizeInBits(), false /* isSigned */);
  Instruction *LShrInst =
      BinaryOperator::CreateLShr(TargetSextInst, ShiftAmount);
  RaisedBB->getInstList().push_back(LShrInst);
  // Truncate LShrInst to get the high bytes
  Instruction *HighBytesInst =
      CastInst::Create(Instruction::Trunc, LShrInst, UseRegTy);
  RaisedBB->getInstList().push_back(HighBytesInst);
  // Update the value mapping of DefReg_1
  raisedValues->setPhysRegSSAValue(DefReg_1, MI.getParent()->getNumber(),
                                   HighBytesInst);

  return true;
}

bool X86MachineInstructionRaiser::raiseMoveImmToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  bool success = false;

  switch (Opcode) {
  case X86::MOV8ri:
  case X86::MOV16ri:
  case X86::MOV32ri:
  case X86::MOV64ri:
  case X86::MOV64ri32: {
    unsigned DestOpIndex = 0, SrcOpIndex = 1;
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    const MachineOperand &SrcOp = MI.getOperand(SrcOpIndex);
    assert(MI.getNumExplicitOperands() == 2 && DestOp.isReg() &&
           SrcOp.isImm() &&
           "Expecting exactly two operands for move imm-to-reg instructions");

    unsigned int DstPReg = DestOp.getReg();
    int64_t SrcImm = SrcOp.getImm();
    Type *ImmTy = getImmOperandType(MI, 1);
    Value *SrcValue = ConstantInt::get(ImmTy, SrcImm);

    SrcValue = castValue(SrcValue, getPhysRegType(DstPReg),
                         getRaisedBasicBlock(MI.getParent()));

    // Check if the immediate value corresponds to a global variable.
    if (SrcImm > 0) {
      Value *GV = getGlobalVariableValueAt(MI, SrcImm);
      if (GV != nullptr) {
        SrcValue = GV;
      }
    }

    // Update the value mapping of dstReg
    raisedValues->setPhysRegSSAValue(DstPReg, MI.getParent()->getNumber(),
                                     SrcValue);
    success = true;
  } break;
  default:
    assert(false && "Unhandled move imm-to-reg instruction");
    break;
  }
  return success;
}

bool X86MachineInstructionRaiser::raiseMoveRegToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  int MBBNo = MI.getParent()->getNumber();
  LLVMContext &Ctx(MF.getFunction().getContext());

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  bool Success = false;
  unsigned DstIndex = 0, Src1Index = 1, Src2Index = 2;
  assert(
      (MI.getNumExplicitOperands() == 2 || MI.getNumExplicitOperands() == 4) &&
      MI.getOperand(DstIndex).isReg() &&
      (MI.getOperand(Src1Index).isReg() || MI.getOperand(Src2Index).isReg()) &&
      "Expecting exactly two or four operands for move reg-to-reg "
      "instructions");

  unsigned int DstPReg = MI.getOperand(DstIndex).getReg();

  // Get source operand value
  Value *SrcValue = nullptr;
  if (MI.getNumExplicitOperands() == 2)
    SrcValue = getRegOperandValue(MI, Src1Index);
  else if (MI.getNumExplicitOperands() == 4)
    SrcValue = getRegOperandValue(MI, Src2Index);
  else
    assert(false &&
           "Unexpected operand numbers for move reg-to-reg instruction");

  switch (Opcode) {
  case X86::MOVSX16rr8:
  case X86::MOVSX32rr8:
  case X86::MOVSX32rr16:
  case X86::MOVSX64rr8:
  case X86::MOVSX64rr16:
  case X86::MOVSX64rr32:
  case X86::MOVZX16rr8:
  case X86::MOVZX32rr8:
  case X86::MOVZX32rr16:
  case X86::MOVZX64rr8:
  case X86::MOVZX64rr16: {
    Type *Ty = nullptr;
    Instruction::CastOps Cast;
    // Check for sanity of source value
    assert(SrcValue &&
           "Encountered instruction with undefined source register");

    switch (Opcode) {
    case X86::MOVSX16rr8: {
      assert(is16BitPhysReg(DstPReg) &&
             "Not found expected 16-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt16Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVSX32rr8:
    case X86::MOVSX32rr16: {
      assert(is32BitPhysReg(DstPReg) &&
             "Not found expected 32-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt32Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVSX64rr8:
    case X86::MOVSX64rr16:
    case X86::MOVSX64rr32: {
      assert(is64BitPhysReg(DstPReg) &&
             "Not found expected 64-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt64Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVZX16rr8: {
      assert(is16BitPhysReg(DstPReg) &&
             "Not found expected 16-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt16Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    case X86::MOVZX32rr8:
    case X86::MOVZX32rr16: {
      assert(is32BitPhysReg(DstPReg) &&
             "Not found expected 32-bit destination register - movzx "
             "instruction");
      Ty = Type::getInt32Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    case X86::MOVZX64rr8:
    case X86::MOVZX64rr16: {
      assert(is64BitPhysReg(DstPReg) &&
             "Not found expected 64-bit destination register - movzx "
             "instruction");
      Ty = Type::getInt64Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    default:
      assert(false &&
             "Should not reach here! - mov with extension instruction");
    }
    assert(Ty != nullptr &&
           "Failed to set type - mov with extension instruction");
    // Now create the cast instruction corresponding to the instruction.
    CastInst *CInst = CastInst::Create(Cast, SrcValue, Ty);
    RaisedBB->getInstList().push_back(CInst);

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, CInst);
    Success = true;
  } break;
  case X86::MOV64rr:
  case X86::MOV32rr:
  case X86::MOV16rr:
  case X86::MOV8rr: {
    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
    unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src1Index);

    // Verify sanity of the instruction.
    assert(DstPRegSize != 0 && DstPRegSize == SrcPRegSize &&
           "Unexpected sizes of source and destination registers size differ "
           "in mov instruction");
    assert(SrcValue &&
           "Encountered mov instruction with undefined source register");
    assert(SrcValue->getType()->isSized() &&
           "Unsized source value in move instruction");
    MachineOperand MO = MI.getOperand(Src1Index);
    assert(MO.isReg() && "Unexpected non-register operand");
    SrcValue = matchSSAValueToSrcRegSize(MI, MO.getReg());

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SrcValue);
    Success = true;
  } break;
  case X86::CMOV16rr:
  case X86::CMOV32rr:
  case X86::CMOV64rr: {
    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
    unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src2Index);

    // Verify sanity of the instruction.
    assert(DstPRegSize != 0 && DstPRegSize == SrcPRegSize &&
           "Unexpected sizes of source and destination registers size differ "
           "in cmovcc instruction");
    assert(SrcValue &&
           "Encountered cmovcc instruction with undefined source register");
    assert(SrcValue->getType()->isSized() &&
           "Unsized source value in cmovcc instruction");
    MachineOperand MO = MI.getOperand(Src2Index);
    assert(MO.isReg() && "Unexpected non-register operand");
    SrcValue = matchSSAValueToSrcRegSize(MI, MO.getReg());

    // Get destination operand value
    Value *DstValue = getRegOrArgValue(DstPReg, MBBNo);
    Value *TrueValue = ConstantInt::getTrue(Ctx);
    Value *FalseValue = ConstantInt::getFalse(Ctx);
    CmpInst::Predicate Pred = CmpInst::Predicate::BAD_ICMP_PREDICATE;
    Value *CMOVCond = nullptr;

    switch (X86::getCondFromCMov(MI)) {
    case X86::COND_NE: {
      // Check if ZF == 0
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising CMOVNE!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      CMOVCond = new ICmpInst(Pred, ZFValue, FalseValue, "Cond_CMOVNE");
    } break;
    case X86::COND_E: {
      // Check if ZF == 1
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising CMOVE!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      CMOVCond = new ICmpInst(Pred, ZFValue, TrueValue, "Cond_CMOVE");
    } break;
    case X86::COND_A: {
      // Check CF == 0 and ZF == 0
      Value *CFValue = getRegOrArgValue(EFLAGS::CF, MBBNo);
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert((CFValue != nullptr) && (ZFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVA!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // CF or ZF
      BinaryOperator *CFZFOrCond =
          BinaryOperator::CreateOr(CFValue, ZFValue, "CFZFOR_CMOVA");
      RaisedBB->getInstList().push_back(CFZFOrCond);
      // Test CF == 0 and ZF == 0
      CMOVCond = new ICmpInst(Pred, CFZFOrCond, FalseValue, "Cond_CMOVA");
    } break;
    case X86::COND_L: {
      // Check SF != OF
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
      assert((SFValue != nullptr) && (OFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVL!");
      Pred = CmpInst::Predicate::ICMP_NE;
      // Test SF != OF
      CMOVCond = new ICmpInst(Pred, SFValue, OFValue, "Cond_CMOVL");
    } break;
    case X86::COND_G: {
      // Check ZF == 0 and SF == OF
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
      assert((ZFValue != nullptr) && (SFValue != nullptr) &&
             (OFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVG!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare ZF and 0
      CmpInst *ZFCond = new ICmpInst(Pred, ZFValue, FalseValue, "ZFCmp_CMOVG");
      RaisedBB->getInstList().push_back(ZFCond);
      // Test SF == OF
      CmpInst *SFOFCond = new ICmpInst(Pred, SFValue, OFValue, "SFOFCmp_CMOVG");
      RaisedBB->getInstList().push_back(SFOFCond);
      CMOVCond = BinaryOperator::CreateAnd(ZFCond, SFOFCond, "Cond_CMOVG");
    } break;
    case X86::COND_LE: {
      // Check ZF == 1 or SF != OF
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
      assert((ZFValue != nullptr) && (SFValue != nullptr) &&
             (OFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVLE!");

      // Check ZF == 1
      CmpInst *ZFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue,
                                     TrueValue, "ZFCmp_CMOVLE");
      RaisedBB->getInstList().push_back(ZFCond);

      // Test SF != OF
      CmpInst *SFOFCond = new ICmpInst(CmpInst::Predicate::ICMP_NE, SFValue,
                                       OFValue, "SFOFCmp_CMOVLE");
      RaisedBB->getInstList().push_back(SFOFCond);

      CMOVCond = BinaryOperator::CreateOr(ZFCond, SFOFCond, "Cond_CMOVLE");
    } break;
    case X86::COND_NS: {
      // Test SF == 0
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      assert(SFValue != nullptr &&
             "Failed to get EFLAGS value while raising CMOVNS");
      // Construct a compare instruction
      CMOVCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, SFValue, FalseValue,
                              "Cond_CMOVNS");
    } break;
    case X86::COND_INVALID:
      assert(false && "CMOV instruction with invalid condition found");
      break;
    default:
      assert(false && "CMOV instruction with unhandled condition found");
      break;
    }
    RaisedBB->getInstList().push_back(dyn_cast<Instruction>(CMOVCond));

    // Ensure that the types of SrcValue and DstValue match.
    DstValue = castValue(DstValue, SrcValue->getType(), RaisedBB);

    // Generate SelectInst for CMOV instruction
    SelectInst *SI = SelectInst::Create(CMOVCond, SrcValue, DstValue, "CMOV");
    RaisedBB->getInstList().push_back(SI);

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SI);
    Success = true;
  } break;
  default:
    assert(false && "Unhandled move reg-to-reg instruction");
    break;
  }
  return Success;
}

bool X86MachineInstructionRaiser::raiseLEAMachineInstr(const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();

  assert(MI.getNumExplicitOperands() == 6 &&
         "Unexpected number of arguments of lea instruction");
  // Get dest operand
  MachineOperand DestOp = MI.getOperand(0);
  assert(DestOp.isReg() &&
         "Unhandled non-register destination operand in lea instruction");
  unsigned int DestReg = DestOp.getReg();

  int OpIndex = X86II::getMemoryOperandNo(MI.getDesc().TSFlags);
  assert(OpIndex >= 0 && "Failed to get first operand of addressing-mode "
                         "expression in lea instruction");

  MachineOperand BaseRegOp = MI.getOperand(OpIndex + X86::AddrBaseReg);
  assert(BaseRegOp.isReg() &&
         "Unhandled non-register BaseReg operand in lea instruction");
  unsigned int BaseReg = BaseRegOp.getReg();
  Value *EffectiveAddrValue = nullptr;

  // If the basereg refers stack, get the stack allocated object value
  uint64_t BaseSupReg = find64BitSuperReg(BaseReg);
  if ((BaseSupReg == x86RegisterInfo->getStackRegister()) ||
      (BaseSupReg == x86RegisterInfo->getFramePtr())) {
    // Get index of memory reference in the instruction.
    int memoryRefOpIndex = getMemoryRefOpIndex(MI);
    // Should have found the index of the memory reference operand
    assert(memoryRefOpIndex != -1 && "Unable to find memory reference "
                                     "operand of a load/store instruction");
    X86AddressMode memRef = llvm::getAddressFromInstr(&MI, memoryRefOpIndex);
    EffectiveAddrValue = getStackAllocatedValue(MI, memRef, false);
  } else {
    MachineOperand ScaleAmtOp = MI.getOperand(OpIndex + X86::AddrScaleAmt);
    assert(ScaleAmtOp.isImm() &&
           "Unhandled non-immediate ScaleAmt operand in lea instruction");

    MachineOperand IndexRegOp = MI.getOperand(OpIndex + X86::AddrIndexReg);
    assert(IndexRegOp.isReg() &&
           "Unhandled non-register IndexReg operand in lea instruction");

    unsigned int IndexReg = IndexRegOp.getReg();

    MachineOperand SegmentRegOp = MI.getOperand(OpIndex + X86::AddrSegmentReg);
    assert(SegmentRegOp.getReg() == X86::NoRegister &&
           "Unhandled vaule of SegmentReg operand in lea instruction");

    MachineOperand Disp = MI.getOperand(OpIndex + X86::AddrDisp);
    assert(Disp.isImm() &&
           "Unhandled non-immediate Disp operand in lea instruction");

    // Check the sanity of register sizes
    if ((Opcode == X86::LEA64r) || (Opcode == X86::LEA64_32r)) {
      // lea64mem (see LEA64 and LEA64_32r description in
      // X86InstrArithmetic.td)
      assert((is64BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-64 bit base register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is64BitPhysReg(IndexReg)) &&
             "Unexpected index register type in lea instruction");
      assert(IndexReg != x86RegisterInfo->getStackRegister() &&
             "Unexpected stack pointer register as indexReg operand of lea "
             "instruction");
      if (Opcode == X86::LEA64_32r) {
        assert(is32BitPhysReg(DestReg) &&
               "Unexpected non-32 bit destination register in lea "
               "instruction");
      } else {
        assert(is64BitPhysReg(DestReg) &&
               "Unexpected non-32 bit dest register in lea instruction");
      }
    } else if (Opcode == X86::LEA32r) {
      assert((is32BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-32 bit base register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is32BitPhysReg(IndexReg)) &&
             "Unexpected indext register type in lea instruction");
      assert(is32BitPhysReg(DestReg) &&
             "Unexpected non-32 bit dest register in lea instruction");
    } else if (Opcode == X86::LEA16r) {
      assert((is16BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-16 bit source register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is16BitPhysReg(IndexReg)) &&
             "Unexpected indext register type in lea instruction");
      assert(is16BitPhysReg(DestReg) &&
             "Unexpected non-16 bit dest register in lea instruction");
    }
    if (BaseReg == X86::RIP)
      EffectiveAddrValue = createPCRelativeAccesssValue(MI);
    else
      EffectiveAddrValue = getMemoryAddressExprValue(MI);
  }

  assert((EffectiveAddrValue != nullptr) &&
         "Failed to get effective address value");

  unsigned DestRegSize = getPhysRegSizeInBits(DestReg);
  Type *DstTy = Type::getIntNTy(MF.getFunction().getContext(), DestRegSize);
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  // Cast the result as needed
  EffectiveAddrValue = castValue(EffectiveAddrValue, DstTy, RaisedBB);

  // Update the value mapping of DestReg
  raisedValues->setPhysRegSSAValue(DestReg, MI.getParent()->getNumber(),
                                   EffectiveAddrValue);
  return true;
}

bool X86MachineInstructionRaiser::raiseBinaryOpRegToRegMachineInstr(
    const MachineInstr &MI) {

  auto MCID = MI.getDesc();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Convenience variables for instructions with a dest and one or two
  // operands
  const unsigned DestOpIndex = 0, UseOp1Index = 1, UseOp2Index = 2;
  std::vector<Value *> Uses;
  int MBBNo = MI.getParent()->getNumber();

  for (const MachineOperand &MO : MI.explicit_uses()) {
    assert(MO.isReg() &&
           "Unexpected non-register operand in binary op instruction");
    auto UseOpIndex = MI.findRegisterUseOperandIdx(MO.getReg(), false, nullptr);
    Value *SrcValue = getRegOperandValue(MI, UseOpIndex);

    Uses.push_back(SrcValue);
  }

  // Verify the instruction has 1 or 2 use operands
  assert((Uses.size() == 1 || ((Uses.size() == 2))) &&
         "Unexpected number of operands in register binary op instruction");

  // If the instruction has two use operands, ensure that their values are
  // of the same type and non-pointer type.
  if (Uses.size() == 2) {
    Value *Src1Value = Uses.at(0);
    Value *Src2Value = Uses.at(1);
    // The user operand values can be null if the instruction is 'xor op
    // op'. See below.
    if ((Src1Value != nullptr) && (Src2Value != nullptr)) {
      // If this is a pointer type, convert it to int type
      while (Src1Value->getType()->isPointerTy()) {
        PtrToIntInst *ConvPtrToInst = new PtrToIntInst(
            Src1Value, Src1Value->getType()->getPointerElementType());
        RaisedBB->getInstList().push_back(ConvPtrToInst);
        Src1Value = ConvPtrToInst;
      }

      // If this is a pointer type, convert it to int type
      while (Src2Value->getType()->isPointerTy()) {
        PtrToIntInst *ConvPtrToInst = new PtrToIntInst(
            Src2Value, Src2Value->getType()->getPointerElementType());
        RaisedBB->getInstList().push_back(ConvPtrToInst);
        Src2Value = ConvPtrToInst;
      }
      assert(Src1Value->getType()->isIntegerTy() &&
             Src2Value->getType()->isIntegerTy() &&
             "Unhandled operand value types in reg-to-reg binary op "
             "instruction");
      if (Src1Value->getType() != Src2Value->getType()) {
        // Cast the second operand to the type of second.
        // NOTE : The choice of target cast type is rather arbitrary. May
        // need a closer look.
        Type *DestValueTy = Src1Value->getType();
        Instruction *CInst = CastInst::Create(
            CastInst::getCastOpcode(Src2Value, false, DestValueTy, false),
            Src2Value, DestValueTy);
        RaisedBB->getInstList().push_back(CInst);
        Src2Value = CInst;
      }
      Uses[0] = Src1Value;
      Uses[1] = Src2Value;
    }
  }

  // Figure out the destination register, corresponding value and the
  // binary operator.
  unsigned int dstReg = X86::NoRegister;
  Value *dstValue = nullptr;
  unsigned opc = MI.getOpcode();
  // Construct the appropriate binary operation instruction
  switch (opc) {
  case X86::ADD8rr:
  case X86::ADD32rr:
  case X86::ADD64rr:
    // Verify the def operand is a register.
    assert(MI.getOperand(DestOpIndex).isReg() &&
           "Expecting destination of add instruction to be a register "
           "operand");
    assert((MCID.getNumDefs() == 1) &&
           "Unexpected number of defines in an add instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "add");
    dstReg = MI.getOperand(DestOpIndex).getReg();
    dstValue = BinaryOperator::CreateNSWAdd(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Set SF and ZF based on dstValue; technically OF, AF, CF and PF also
    // needs to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI, dstValue);

    // Update the value of dstReg
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
    break;
  case X86::IMUL16rr:
  case X86::IMUL32rr:
  case X86::IMUL64rr:
    // Verify the def operand is a register.
    assert(MI.getOperand(DestOpIndex).isReg() &&
           "Expecting destination of mul instruction to be a register "
           "operand");
    assert((MCID.getNumDefs() == 1) &&
           "Unexpected number of defines in a mul instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "mul");
    dstReg = MI.getOperand(DestOpIndex).getReg();
    dstValue = BinaryOperator::CreateNSWMul(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Setting EFLAG bits does not seem to matter, so not setting
    // Set the dstReg value
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
    break;
  case X86::IMUL64r: {
    assert(MCID.getNumDefs() == 0 && MCID.getNumImplicitDefs() == 3 &&
           MCID.getNumImplicitUses() == 1 &&
           "Unexpected operands in imul instruction");
    // Find first source operand - this is the implicit operand AL/AX/EAX/RAX
    const MCPhysReg Src1Reg = MCID.ImplicitUses[0];
    assert(find64BitSuperReg(Src1Reg) == X86::RAX &&
           "Unexpected implicit register in imul instruction");
    // Find second operand - this is the explicit operand of the instruction
    std::vector<MCPhysReg> SrcRegs;
    for (const MachineOperand &MO : MI.explicit_uses()) {
      assert(MO.isReg() &&
             "Unexpected non-register operand in binary op instruction");
      SrcRegs.push_back(MO.getReg());
    }
    // Ensure that there is only one explicit source operand
    assert(SrcRegs.size() == 1 &&
           "Unexpected number of source register operands in imul instruction");
    // Check the sizes of source operands are the same
    const MCPhysReg Src2Reg = SrcRegs[0];
    unsigned int SrcOpSize = getPhysRegSizeInBits(Src1Reg);
    assert(getPhysRegSizeInBits(Src1Reg) == getPhysRegSizeInBits(Src2Reg) &&
           "Mismatched size of implicit source register and explicit source "
           "register");
    // Get the value of Src1Reg and Src2Reg
    Value *Src1Value = getRegOrArgValue(Src1Reg, MBBNo);
    Value *Src2Value = getRegOrArgValue(Src2Reg, MBBNo);
    assert((Src1Value != nullptr) && (Src2Value != nullptr) &&
           "Unexpected null source operand value in imul instruction");
    assert(Src1Value->getType()->isIntegerTy() &&
           Src2Value->getType()->isIntegerTy() &&
           "Unexpected non-integer type source operands in imul instruction");
    LLVMContext &Ctx(MF.getFunction().getContext());
    // Widen the source values since the result of th emultiplication
    Type *WideTy = Type::getIntNTy(Ctx, SrcOpSize * 2);
    CastInst *Src1ValueDT =
        CastInst::Create(CastInst::getCastOpcode(Src1Value, true, WideTy, true),
                         Src1Value, WideTy);
    RaisedBB->getInstList().push_back(Src1ValueDT);

    CastInst *Src2ValueDT =
        CastInst::Create(CastInst::getCastOpcode(Src2Value, true, WideTy, true),
                         Src2Value, WideTy);
    RaisedBB->getInstList().push_back(Src2ValueDT);
    // Multiply the values
    Instruction *FullProductValue =
        BinaryOperator::CreateNSWMul(Src1ValueDT, Src2ValueDT);
    RaisedBB->getInstList().push_back(FullProductValue);
    // Shift amount equal to size of source operand
    Value *ShiftAmountVal =
        ConstantInt::get(FullProductValue->getType(), SrcOpSize);
    Value *ZeroValueDT =
        ConstantInt::get(FullProductValue->getType(), 0, false /* isSigned */);

    // Split the value into ImplicitDefs[0]:ImplicitDefs[1]
    // Compute shr of FullProductValue
    Instruction *ShrDT =
        BinaryOperator::CreateLShr(FullProductValue, ShiftAmountVal);
    RaisedBB->getInstList().push_back(ShrDT);
    // Now generate ShrDT OR 0
    Instruction *OrDT = BinaryOperator::CreateOr(ShrDT, ZeroValueDT);
    RaisedBB->getInstList().push_back(OrDT);
    // Cast OrValDT to SrcOpSize
    Type *SrcValTy = Src1Value->getType();
    CastInst *ProductUpperValue = CastInst::Create(
        CastInst::getCastOpcode(OrDT, true, SrcValTy, true), OrDT, SrcValTy);
    RaisedBB->getInstList().push_back(ProductUpperValue);
    // Set the value of ImplicitDef[0] as ProductLowreHalfValue
    raisedValues->setPhysRegSSAValue(MCID.ImplicitDefs[0], MBBNo,
                                     ProductUpperValue);

    // Now generate and instruction to get lower half value
    Value *MaskValue = Constant::getAllOnesValue(SrcValTy);
    Instruction *MaskValDT =
        CastInst::Create(CastInst::getCastOpcode(MaskValue, true, WideTy, true),
                         MaskValue, WideTy);
    RaisedBB->getInstList().push_back(MaskValDT);

    Instruction *AndValDT =
        BinaryOperator::CreateAnd(FullProductValue, MaskValDT);
    RaisedBB->getInstList().push_back(AndValDT);
    // Cast AndValDT to SrcOpSize
    CastInst *ProductLowerHalfValue = CastInst::Create(
        CastInst::getCastOpcode(AndValDT, true, SrcValTy, true), AndValDT,
        SrcValTy);
    RaisedBB->getInstList().push_back(ProductLowerHalfValue);
    // Set the value of ImplicitDef[1] as ProductLowerHalfValue
    raisedValues->setPhysRegSSAValue(MCID.ImplicitDefs[1], MBBNo,
                                     ProductLowerHalfValue);
    // Set OF and CF flags to 0 if upper half of the result is 0; else to 1.
    Value *ZeroValue = ConstantInt::get(SrcValTy, 0, false /* isSigned */);

    Instruction *ZFTest =
        new ICmpInst(CmpInst::Predicate::ICMP_EQ, ProductLowerHalfValue,
                     ZeroValue, "Test_Zero");

    RaisedBB->getInstList().push_back(ZFTest);
    raisedValues->setPhysRegSSAValue(X86RegisterUtils::EFLAGS::OF, MBBNo,
                                     ZFTest);
    raisedValues->setPhysRegSSAValue(X86RegisterUtils::EFLAGS::SF, MBBNo,
                                     ZFTest);
  } break;
  case X86::AND8rr:
  case X86::AND16rr:
  case X86::AND32rr:
  case X86::AND64rr:
  case X86::OR8rr:
  case X86::OR16rr:
  case X86::OR32rr:
  case X86::OR64rr:
  case X86::XOR8rr:
  case X86::XOR16rr:
  case X86::XOR32rr:
  case X86::XOR64rr: {
    // Verify the def operand is a register.
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    const MachineOperand &Use2Op = MI.getOperand(UseOp2Index);
    assert(DestOp.isReg() && "Expecting destination of xor instruction to "
                             "be a register operand");
    assert((MCID.getNumDefs() == 1) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a xor instruction");
    dstReg = DestOp.getReg();
    // Generate an or instruction to set the zero flag if the
    // operands are the same. An instruction such as 'xor $ecx, ecx' is
    // generated to set the register value to 0.
    if ((MI.findTiedOperandIdx(1) == 0) && (dstReg == Use2Op.getReg())) {
      // No instruction to generate. Just set destReg value to 0.
      Type *DestTy = getPhysRegOperandType(MI, 0);
      Value *Val = ConstantInt::get(DestTy, 0, false /* isSigned */);
      dstValue = Val;
      // Set SF and ZF knowing that the value is 0
      raisedValues->setEflagValue(EFLAGS::SF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::ZF, MBBNo, true);
    } else {
      assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
             "Unhandled situation: register used before initialization in "
             "xor");
      switch (opc) {
      case X86::AND8rr:
      case X86::AND16rr:
      case X86::AND32rr:
      case X86::AND64rr:
        dstValue = BinaryOperator::CreateAnd(Uses.at(0), Uses.at(1));
        break;
      case X86::OR8rr:
      case X86::OR16rr:
      case X86::OR32rr:
      case X86::OR64rr:
        dstValue = BinaryOperator::CreateOr(Uses.at(0), Uses.at(1));
        break;
      case X86::XOR8rr:
      case X86::XOR16rr:
      case X86::XOR32rr:
      case X86::XOR64rr:
        dstValue = BinaryOperator::CreateXor(Uses.at(0), Uses.at(1));
        break;
      default:
        assert(false && "Reached unexpected location");
      }
      if (isa<Instruction>(dstValue))
        RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
      // Set SF and ZF based on dstValue; technically PF also needs
      // to be set but ignoring for now.
      raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI, dstValue);
      raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI, dstValue);
    }
    // Clear OF and CF
    raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
    raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
    // Update the value of dstReg
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  } break;
  case X86::TEST8rr:
  case X86::TEST16rr:
  case X86::TEST32rr:
  case X86::TEST64rr:
    assert((MCID.getNumDefs() == 0) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a test instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "test");
    dstReg = X86::EFLAGS;
    dstValue = BinaryOperator::CreateAnd(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Clear OF and CF
    raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
    raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
    // Set SF and ZF based on dstValue; technically PF also needs
    // to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI, dstValue);
    break;
  case X86::NEG8r:
  case X86::NEG16r:
  case X86::NEG32r:
  case X86::NEG64r: {
    // Verify source and dest are tied and are registers
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    assert(DestOp.isTied() &&
           (MI.findTiedOperandIdx(DestOpIndex) == UseOp1Index) &&
           "Expect tied operand in neg instruction");
    assert(DestOp.isReg() && "Expect reg operand in neg instruction");
    assert((MCID.getNumDefs() == 1) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a neg instruction");
    dstReg = DestOp.getReg();
    Value *SrcOp = Uses.at(0);
    dstValue = BinaryOperator::CreateNeg(SrcOp);
    // Set CF to 0 if source operand is 0
    // Note: Add this instruction _before_ adding the result of neg
    raisedValues->testAndSetEflagSSAValue(EFLAGS::CF, MI, dstValue);
    // Now add the neg instruction
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Now set up the flags according to the result
    // Set SF and ZF based on dstValue; technically PF also needs
    // to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI, dstValue);

    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  } break;
  case X86::NOT8r:
  case X86::NOT16r:
  case X86::NOT32r:
  case X86::NOT64r: {
    // Verify source and dest are tied and are registers
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    assert(DestOp.isTied() &&
           (MI.findTiedOperandIdx(DestOpIndex) == UseOp1Index) &&
           "Expect tied operand in not instruction");
    assert(DestOp.isReg() && "Expect reg operand in not instruction");
    assert((MCID.getNumDefs() == 1) &&
           "Unexpected defines in a not instruction");
    dstReg = DestOp.getReg();
    Value *SrcOp = Uses.at(0);
    dstValue = BinaryOperator::CreateNot(SrcOp);
    // No EFLAGS are effected
    // Add the not instruction
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));

    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  } break;

  default:
    assert(false && "Unhandled binary instruction");
  }

  return true;
}

bool X86MachineInstructionRaiser::raiseBinaryOpMemToRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {
  unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();

  assert((MIDesc.getNumDefs() == 1) &&
         "Encountered memory load instruction with more than 1 defs");
  unsigned int DestIndex = 0;
  const MachineOperand &DestOp = MI.getOperand(DestIndex);
  assert(DestOp.isReg() &&
         "Expect destination register operand in binary reg/mem instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  unsigned int DestPReg = DestOp.getReg();
  unsigned int MemAlignment = getInstructionMemOpSize(Opcode);
  Type *DestopTy = getPhysRegOperandType(MI, DestIndex);
  Value *DestValue = getRegOrArgValue(DestPReg, MI.getParent()->getNumber());
  assert(DestValue != nullptr &&
         "Encountered instruction with undefined register");

  // Verify sanity of the instruction.
  assert((getPhysRegOperandSize(MI, DestIndex) == MemAlignment) &&
         "Mismatched destination register size and instruction size of binary "
         "op instruction");

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an LoadInst that loads an address in memory.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GetElementPtrInst>(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in binary mem op instruction");
  bool IsMemRefGlobalVal = false;
  // If it is an effective address
  if (isEffectiveAddrValue(MemRefValue)) {
    // Check if this is a load if a global value
    if (isa<LoadInst>(MemRefValue)) {
      LoadInst *LdInst = dyn_cast<LoadInst>(MemRefValue);
      if (isa<GlobalValue>(LdInst->getPointerOperand())) {
        IsMemRefGlobalVal = true;
      }
    } else {
      // This is an effective address computation
      // Cast it to a pointer of type of destination operand.
      PointerType *PtrTy = PointerType::get(DestopTy, 0);
      IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(ConvIntToPtr);
      MemRefValue = ConvIntToPtr;
    }
  }
  Value *LoadValue = nullptr;
  if (IsMemRefGlobalVal) {
    // Load the global value.
    LoadInst *LdInst =
        new LoadInst(dyn_cast<LoadInst>(MemRefValue)->getPointerOperand());
    LdInst->setAlignment(MaybeAlign(MemAlignment));
    LoadValue = LdInst;
  } else {
    LoadInst *LdInst = new LoadInst(MemRefValue);
    LdInst->setAlignment(MaybeAlign(MemAlignment));
    LoadValue = LdInst;
  }
  // Insert the instruction that loads memory reference
  RaisedBB->getInstList().push_back(dyn_cast<Instruction>(LoadValue));
  Instruction *BinOpInst = nullptr;

  // Generate cast instruction to ensure source and destination types are
  // consistent, as needed.
  LoadValue = castValue(LoadValue, DestValue->getType(), RaisedBB);

  switch (Opcode) {
  case X86::ADD64rm:
  case X86::ADD32rm:
  case X86::ADD16rm:
  case X86::ADD8rm: {
    // Create add instruction
    BinOpInst = BinaryOperator::CreateAdd(DestValue, LoadValue);
  } break;
  case X86::AND64rm:
  case X86::AND32rm:
  case X86::AND16rm:
  case X86::AND8rm: {
    // Create and instruction
    BinOpInst = BinaryOperator::CreateAnd(DestValue, LoadValue);
  } break;
  case X86::OR32rm: {
    // Create or instruction
    BinOpInst = BinaryOperator::CreateOr(DestValue, LoadValue);
  } break;
  case X86::IMUL16rm:
  case X86::IMUL32rm: {
    // One-operand form of IMUL
    // Create mul instruction
    BinOpInst = BinaryOperator::CreateMul(DestValue, LoadValue);
  } break;
  case X86::IMUL16rmi:
  case X86::IMUL16rmi8:
  case X86::IMUL32rmi:
  case X86::IMUL32rmi8:
  case X86::IMUL64rmi8:
  case X86::IMUL64rmi32: {
    // Two-operand form of IMUL
    // Get index of memory reference in the instruction.
    int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
    // The index of the memory reference operand should be 1
    assert(MemoryRefOpIndex == 1 &&
           "Unexpected memory reference operand index in imul instruction");
    const MachineOperand &SecondSourceOp =
        MI.getOperand(MemoryRefOpIndex + X86::AddrNumOperands);
    // Second source should be an immediate.
    assert(SecondSourceOp.isImm() &&
           "Expect immediate operand in imul instruction");
    // Construct the value corresponding to immediate operand
    Value *SecondSourceVal =
        ConstantInt::get(LoadValue->getType(), SecondSourceOp.getImm());
    // Create mul instruction
    BinOpInst = BinaryOperator::CreateMul(SecondSourceVal, LoadValue);
  } break;
  default:
    assert(false && "Unhandled binary op mem to reg instruction ");
  }
  // Add instruction to block
  RaisedBB->getInstList().push_back(BinOpInst);

  // Update PhysReg to Value map
  raisedValues->setPhysRegSSAValue(DestPReg, MI.getParent()->getNumber(),
                                   BinOpInst);
  return true;
}

bool X86MachineInstructionRaiser::raiseLoadIntToFloatRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {

  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 0 && "Expect memory operand of floating-point "
                                  "load instruction at index 0");
  assert(MIDesc.getNumDefs() == 0 &&
         "Expect no defs in floating-point load instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in FPU load op instruction");

  LLVMContext &llvmContext(MF.getFunction().getContext());
  if (IsPCRelMemRef) {
    // If it is a PC-relative mem ref, memRefValue is a
    // global value loaded from PC-relative memory location. If it is a
    // derived type value, get its element pointer.
    Type *MemRefValueTy = MemRefValue->getType();
    if (!MemRefValueTy->isFloatingPointTy()) {
      assert(MemRefValueTy->isPointerTy() &&
             "Unhandled non-pointer type found while attempting to push value "
             "to FPU register stack.");
      Type *MemRefValPtrElementTy = MemRefValueTy->getPointerElementType();
      switch (MemRefValPtrElementTy->getTypeID()) {
      case Type::ArrayTyID: {
        assert(MemRefValPtrElementTy->getArrayNumElements() == 1 &&
               "Unexpected number of array elements in value being cast to "
               "float");
        // Make sure the array element type is integer or floating point
        // type.
        Type *ArrElemTy = MemRefValPtrElementTy->getArrayElementType();
        assert((ArrElemTy->isIntegerTy() || ArrElemTy->isFloatingPointTy()) &&
               "Unexpected type of data referenced in FPU register stack "
               "load instruction");
        // Get the element
        Value *IndexOne = ConstantInt::get(llvmContext, APInt(32, 1));
        Instruction *GetElem = GetElementPtrInst::CreateInBounds(
            MemRefValPtrElementTy, MemRefValue, {IndexOne, IndexOne}, "",
            RaisedBB);
        MemRefValue = GetElem;
      } break;
      // Primitive types that need not be reached into.
      case Type::IntegerTyID:
        break;
      default: {
        assert(false && "Encountered value with type whose cast to float is "
                        "not yet handled");
      } break;
      }
    }
  }
  // If it is an effective address value, convert it to a pointer to
  // the type of load reg.
  if (isEffectiveAddrValue(MemRefValue)) {
    assert(false &&
           "*** Unhandled situation. Need to implement support correctly");
    Type *PtrTy = MemRefValue->getType();
    IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
    RaisedBB->getInstList().push_back(ConvIntToPtr);
    MemRefValue = ConvIntToPtr;
  }
  assert(MemRefValue->getType()->isPointerTy() &&
         "Pointer type expected in load instruction");
  // Load the value from memory location
  LoadInst *LdInst = new LoadInst(MemRefValue);
  unsigned int MemAlignment = MemRefValue->getType()
                                  ->getPointerElementType()
                                  ->getPrimitiveSizeInBits() /
                              8;
  LdInst->setAlignment(MaybeAlign(MemAlignment));
  RaisedBB->getInstList().push_back(LdInst);

  switch (Opcode) {
  default: {
    assert(false && "Unhandled load floating-point register instruction");
  } break;
  case X86::ILD_F32m:
  case X86::ILD_F64m: {
    Type *FloatTy = Type::getFloatTy(llvmContext);
    assert(LdInst->getType()->isIntegerTy() &&
           "Unexpected non-integter type of source in fild instruction");
    // Cast source to float
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(LdInst, true, FloatTy, true), LdInst, FloatTy);
    RaisedBB->getInstList().push_back(CInst);
    // Push value to top of FPU register stack
    FPURegisterStackPush(CInst);
  } break;
  case X86::LD_F32m: {
    Type *FloatTy = Type::getFloatTy(llvmContext);
    // Cast source to float
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(LdInst, true, FloatTy, true), LdInst, FloatTy);
    RaisedBB->getInstList().push_back(CInst);
    // Push value to top of FPU register stack
    FPURegisterStackPush(CInst);
  }
  }
  return true;
}

bool X86MachineInstructionRaiser::raiseStoreIntToFloatRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {

  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 0 && "Expect memory operand of floating-point "
                                  "load instruction at index 0");
  assert(MIDesc.getNumDefs() == 0 &&
         "Expect no defs in floating-point load instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in FPU store op instruction");

  LLVMContext &llvmContext(MF.getFunction().getContext());
  if (IsPCRelMemRef) {
    // If it is a PC-relative mem ref, memRefValue is a global value loaded
    // from PC-relative memory location. If it is a derived type value, get
    // its element pointer.
    Type *MemRefValueTy = MemRefValue->getType();
    if (!MemRefValueTy->isFloatingPointTy()) {
      assert(MemRefValueTy->isPointerTy() &&
             "Unhandled non-pointer type found while attempting to load value "
             "from FPU register stack.");
      Type *MemRefValPtrElementTy = MemRefValueTy->getPointerElementType();
      switch (MemRefValPtrElementTy->getTypeID()) {
      case Type::ArrayTyID: {
        assert(MemRefValPtrElementTy->getArrayNumElements() == 1 &&
               "Unexpected number of array elements in value being cast to "
               "float");
        // Make sure the array element type is integer or floating point
        // type.
        Type *ArrElemTy = MemRefValPtrElementTy->getArrayElementType();
        assert((ArrElemTy->isIntegerTy() || ArrElemTy->isFloatingPointTy()) &&
               "Unexpected type of data referenced in FPU register stack "
               "store instruction");
        // Get the element
        Value *IndexOne = ConstantInt::get(llvmContext, APInt(32, 1));
        Instruction *GetElem = GetElementPtrInst::CreateInBounds(
            MemRefValPtrElementTy, MemRefValue, {IndexOne, IndexOne}, "",
            RaisedBB);
        MemRefValue = GetElem;
      } break;
      // Primitive types that need not be reached into.
      case Type::IntegerTyID:
        break;
      default: {
        assert(false && "Encountered value with type whose cast to float is "
                        "not yet handled");
      } break;
      }
    }
  }
  // If it is an effective address value, convert it to a pointer to
  // the type of load reg.
  if (isEffectiveAddrValue(MemRefValue)) {
    assert(false &&
           "*** Unhandled situation. Need to implement support correctly");
    Type *PtrTy = MemRefValue->getType();
    IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
    RaisedBB->getInstList().push_back(ConvIntToPtr);
    MemRefValue = ConvIntToPtr;
  }
  assert(MemRefValue->getType()->isPointerTy() &&
         "Pointer type expected in store instruction");

  switch (Opcode) {
  default: {
    assert(false && "Unhandled store floating-point register instruction");
  } break;
  case X86::ST_FP32m:
  case X86::ST_FP64m: {
    Value *ST0Val = FPURegisterStackTop();
    Type *SrcTy = ST0Val->getType();
    // The value in ST0 is converted to single-precision or double precision
    // floating-point format. So, cast the memRefValue to the PointerType of
    // SrcTy.
    Type *DestElemTy = MemRefValue->getType()->getPointerElementType();
    if (DestElemTy != SrcTy) {
      PointerType *SrcPtrTy = SrcTy->getPointerTo(0);
      Instruction *CInst = CastInst::Create(
          CastInst::getCastOpcode(MemRefValue, true, SrcPtrTy, true),
          MemRefValue, SrcPtrTy);
      RaisedBB->getInstList().push_back(CInst);
      MemRefValue = CInst;
    }
    // Create the store
    StoreInst *StInst = new StoreInst(ST0Val, MemRefValue);
    RaisedBB->getInstList().push_back(StInst);

    // Pop value to top of FPU register stack
    FPURegisterStackPop();
  }
  }
  return true;
}

bool X86MachineInstructionRaiser::raiseMoveFromMemInstr(const MachineInstr &MI,
                                                        Value *MemRefValue) {
  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned LoadOpIndex = 0;
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 1 &&
         "Expect memory operand of a mem move instruction at index 1");
  assert(MIDesc.getNumDefs() == 1 && MI.getOperand(LoadOpIndex).isReg() &&
         "Expect store operand register target");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);
  const MachineOperand &LoadOp = MI.getOperand(LoadOpIndex);
  unsigned int LoadPReg = LoadOp.getReg();
  assert(Register::isPhysicalRegister(LoadPReg) &&
         "Expect destination to be a physical register in move from mem "
         "instruction");

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access), GlobalValue (global
  // data access), an effective address value, element pointer or select
  // instruction.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue) || isa<SelectInst>(MemRefValue) ||
          isa<GetElementPtrInst>(MemRefValue)) &&
         "Unexpected type of memory reference in binary mem op instruction");

  if (IsPCRelMemRef && !isa<GetElementPtrInst>(MemRefValue)) {
    // memRefValue already represents the global value loaded from
    // PC-relative memory location. It is incorrect to generate an
    // additional load of this value. It should be directly used.
    raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                     MemRefValue);
  } else {
    // If it is an effective address value or a select instruction, convert it
    // to a pointer to load register type.
    if ((isEffectiveAddrValue(MemRefValue)) || isa<SelectInst>(MemRefValue)) {
      PointerType *PtrTy =
          PointerType::get(getPhysRegOperandType(MI, LoadOpIndex), 0);
      IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(ConvIntToPtr);
      MemRefValue = ConvIntToPtr;
    }
    assert(MemRefValue->getType()->isPointerTy() &&
           "Pointer type expected in load instruction");
    // Load the value from memory location
    LoadInst *LdInst = new LoadInst(MemRefValue);
    unsigned int MemAlignment = MemRefValue->getType()
                                    ->getPointerElementType()
                                    ->getPrimitiveSizeInBits() /
                                8;
    LdInst->setAlignment(MaybeAlign(MemAlignment));
    RaisedBB->getInstList().push_back(LdInst);

    LLVMContext &Ctx(MF.getFunction().getContext());
    Type *MemTy = nullptr;
    Type *ExtTy = nullptr;
    switch (Opcode) {
    default:
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       LdInst);
      break;
    case X86::MOVSX64rm32:
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt32Ty(Ctx);
      break;
    case X86::MOVZX64rm16:
    case X86::MOVSX64rm16:
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
      break;
    case X86::MOVZX64rm8:
    case X86::MOVSX64rm8:
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
      break;
    case X86::MOVZX32rm8:
    case X86::MOVZX32rm8_NOREX:
    case X86::MOVSX32rm8:
      ExtTy = Type::getInt32Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
      break;
    case X86::MOVZX32rm16:
    case X86::MOVSX32rm16:
      ExtTy = Type::getInt32Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
      break;
    case X86::MOVZX16rm8:
    case X86::MOVSX16rm8:
      ExtTy = Type::getInt16Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
      break;
    case X86::MOVZX16rm16:
    case X86::MOVSX16rm16:
      ExtTy = Type::getInt16Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
      break;
    }
    // Decide based on opcode value and not opcode name??
    bool IsSextInst = instrNameStartsWith(MI, "MOVSX");
    bool IsZextInst = instrNameStartsWith(MI, "MOVZX");

    if (IsSextInst || IsZextInst) {
      assert(((ExtTy != nullptr) && (MemTy != nullptr)) &&
             "Unhandled move from memory instruction");

      // Load value of type memTy
      Value *CInst = castValue(LdInst, MemTy, RaisedBB);

      Instruction *ExtInst;

      // Now extend the value accordingly
      if (IsSextInst) {
        // Sign extend
        ExtInst = new SExtInst(CInst, ExtTy);
      } else {
        // Zero extend
        ExtInst = new ZExtInst(CInst, ExtTy);
      }
      RaisedBB->getInstList().push_back(ExtInst);
      // Update PhysReg to Value map
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       ExtInst);
    } else {
      // This is a normal mov instruction
      // Update PhysReg to Value map
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       LdInst);
    }
  }

  return true;
}

bool X86MachineInstructionRaiser::raiseMoveToMemInstr(const MachineInstr &MI,
                                                      Value *MemRefVal) {
  unsigned int SrcOpIndex = getMemoryRefOpIndex(MI) + X86::AddrNumOperands;

  const MachineOperand &SrcOp = MI.getOperand(SrcOpIndex);

  assert((SrcOp.isImm() || SrcOp.isReg()) &&
         "Register or immediate value source expected in a move to mem "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  unsigned int memAlignment = getInstructionMemOpSize(MI.getOpcode());
  Value *SrcValue = nullptr;
  Type *SrcOpTy = nullptr;

  // If Source op is immediate, create a constant int value
  // of type memory location.
  if (SrcOp.isImm()) {
    SrcOpTy = getImmOperandType(MI, SrcOpIndex);
    SrcValue = ConstantInt::get(SrcOpTy, SrcOp.getImm());
  } else {
    // If it is not an immediate value, get source value
    SrcValue = getRegOperandValue(MI, SrcOpIndex);
    SrcOpTy = getPhysRegOperandType(MI, SrcOpIndex);
  }
  assert(SrcValue != nullptr &&
         "Unable to get source value while raising move to mem instruction");
  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefVal) || isEffectiveAddrValue(MemRefVal) ||
          isa<GlobalValue>(MemRefVal) || isa<GetElementPtrInst>(MemRefVal)) &&
         "Unexpected type of memory reference in mem-to-reg instruction");

  // If memory reference is not a pointer type, cast it to a pointer
  Type *DstMemTy = MemRefVal->getType();
  if (!DstMemTy->isPointerTy()) {
    // Cast it as pointer to SrcOpTy
    PointerType *PtrTy = PointerType::get(SrcOpTy, 0);
    IntToPtrInst *convIntToPtr = new IntToPtrInst(MemRefVal, PtrTy);
    RaisedBB->getInstList().push_back(convIntToPtr);
    MemRefVal = convIntToPtr;
  }

  // Is this a mov instruction?
  bool isMovInst = instrNameStartsWith(MI, "MOV");

  LoadInst *LdInst = nullptr;
  if (!isMovInst) {
    // Load the value from memory location
    LdInst = new LoadInst(MemRefVal);
    LdInst->setAlignment(MaybeAlign(
        MemRefVal->getPointerAlignment(MR->getModule()->getDataLayout())));
    RaisedBB->getInstList().push_back(LdInst);
  }

  // This instruction moves a source value to memory. So, if the types of
  // the source value and that of the memory pointer content are not the
  // same, it is the source value that needs to be cast to match the type of
  // destination (i.e., memory). It needs to be sign extended as needed.
  Type *MatchTy = MemRefVal->getType()->getPointerElementType();
  SrcValue = castValue(SrcValue, MatchTy, RaisedBB);

  StoreInst *StInst = nullptr;
  if (!isMovInst) {
    // If this is not an instruction that just moves SrcValue, generate the
    // instruction that performs the appropriate operation and then store the
    // result in MemRefVal.
    assert((LdInst != nullptr) && "Memory value expected to be loaded while "
                                  "raising binary mem op instruction");
    assert((SrcValue != nullptr) && "Source value expected to be loaded while "
                                    "raising binary mem op instruction");
    switch (MI.getOpcode()) {
    case X86::ADD8mi:
    case X86::ADD8mi8:
    case X86::ADD8mr:
    case X86::ADD16mi:
    case X86::ADD16mi8:
    case X86::ADD16mr:
    case X86::ADD32mi:
    case X86::ADD32mi8:
    case X86::ADD32mr:
    case X86::ADD64mi8:
    case X86::ADD64i32:
    case X86::ADD64mr:
    case X86::INC8m:
    case X86::INC16m:
    case X86::INC32m:
    case X86::INC64m: {
      // Generate Add instruction
      Instruction *BinOpInst = BinaryOperator::CreateAdd(LdInst, SrcValue);
      RaisedBB->getInstList().push_back(BinOpInst);
      SrcValue = BinOpInst;
    } break;
    case X86::DEC8m:
    case X86::DEC16m:
    case X86::DEC32m:
    case X86::DEC64m: {
      Instruction *BinOpInst = BinaryOperator::CreateSub(LdInst, SrcValue);
      RaisedBB->getInstList().push_back(BinOpInst);
      SrcValue = BinOpInst;
    } break;
    default:
      assert(false && "Unhandled non-move mem op instruction");
    }
  }

  assert((SrcValue != nullptr) && "Unexpected null value to be stored while "
                                  "raising binary mem op instruction");
  StInst = new StoreInst(SrcValue, MemRefVal);
  // Push the store instruction.
  StInst->setAlignment(MaybeAlign(memAlignment));
  RaisedBB->getInstList().push_back(StInst);

  return true;
}

// load from memory, apply operation, store back to the same memory
bool X86MachineInstructionRaiser::raiseInplaceMemOpInstr(const MachineInstr &MI,
                                                         Value *MemRefVal) {
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  LLVMContext &Ctx(MF.getFunction().getContext());

  unsigned int memAlignment = getInstructionMemOpSize(MI.getOpcode());

  // Note that not instruction with memory operand loads from MemrefVal,
  // computes not operation on the loaded value and stores it back in the
  // location MemRegVal

  // Load the value from memory location of memRefValue.
  Type *SrcTy = MemRefVal->getType();
  // Get the pointer type of data stored by the instruction
  Type *MemPtrTy = Type::getIntNPtrTy(Ctx, memAlignment * 8);
  // If Cast the value to pointer type of size memAlignment
  if (!SrcTy->isPointerTy() || (SrcTy != MemPtrTy)) {
    CastInst *CInst = CastInst::Create(
        CastInst::getCastOpcode(MemRefVal, false, MemPtrTy, false), MemRefVal,
        MemPtrTy);
    RaisedBB->getInstList().push_back(CInst);
    MemRefVal = CInst;
    SrcTy = MemRefVal->getType();
  }

  // Make sure the value is of pointer type.
  assert(SrcTy->isPointerTy() &&
         "Expect value of load instruction to be of pointer type");
  // Load the value from memory location
  Instruction *SrcValue =
      new LoadInst(SrcTy->getPointerElementType(), MemRefVal, "", false);
  RaisedBB->getInstList().push_back(SrcValue);

  switch (MI.getOpcode()) {
  case X86::NOT16m:
  case X86::NOT16r:
  case X86::NOT32m:
  case X86::NOT32r:
  case X86::NOT64m:
  case X86::NOT64r:
  case X86::NOT8m:
  case X86::NOT8r:
    SrcValue = BinaryOperator::CreateNot(SrcValue);
    break;
  case X86::INC8m:
  case X86::INC16m:
  case X86::INC32m:
  case X86::INC64m:
    SrcValue = BinaryOperator::CreateAdd(
        SrcValue, ConstantInt::get(SrcValue->getType(), 1));
    break;
  default:
    assert(false && "Unhandled instruction type");
  }

  RaisedBB->getInstList().push_back(SrcValue);

  // Store the result back in MemRefVal
  StoreInst *StInst = new StoreInst(SrcValue, MemRefVal);

  StInst->setAlignment(MaybeAlign(memAlignment));
  RaisedBB->getInstList().push_back(StInst);
  return true;
}

// Raise idiv instruction with source operand with value srcValue.
bool X86MachineInstructionRaiser::raiseDivideInstr(const MachineInstr &MI,
                                                   Value *SrcValue) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  LLVMContext &Ctx(MF.getFunction().getContext());

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // idiv uses AX(AH:AL or DX:AX or EDX:EAX or RDX:RAX pairs as dividend and
  // stores the result in the same pair. Additionally, EFLAGS is an implicit
  // def.
  assert(MIDesc.getNumImplicitUses() == 2 && MIDesc.getNumImplicitDefs() == 3 &&
         MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
         "Unexpected number of implicit uses and defs in div instruction");
  MCPhysReg UseDefReg_0 = MIDesc.ImplicitUses[0];
  MCPhysReg UseDefReg_1 = MIDesc.ImplicitUses[1];
  assert((UseDefReg_0 == MIDesc.ImplicitDefs[0]) &&
         (UseDefReg_1 == MIDesc.ImplicitDefs[1]) &&
         "Unexpected use/def registers in div instruction");

  Value *DividendLowBytes =
      getRegOrArgValue(UseDefReg_0, MI.getParent()->getNumber());
  Value *DividendHighBytes =
      getRegOrArgValue(UseDefReg_1, MI.getParent()->getNumber());
  assert((DividendLowBytes != nullptr) && (DividendHighBytes != nullptr) &&
         "Unexpected use before definition in div instruction");
  // Divisor is srcValue.
  // Create a Value representing the dividend.
  // TODO: Not sure how the implicit use registers of IDIV8m are encode.
  // Does the instruction have AX as a single use/def register or does it
  // have 2 use/def registers, viz., AH:AL pair similar to the other IDIV
  // instructions? Handle it when it is encountered.
  assert((DividendLowBytes->getType() == DividendHighBytes->getType()) &&
         "Unexpected types of dividend registers in idiv instruction");
  unsigned int UseDefRegSize =
      DividendLowBytes->getType()->getScalarSizeInBits();
  // Generate the following code
  // %h = lshl DividendHighBytes, UseDefRegSize
  // %f = or %h, DividendLowBytes
  // %quo = idiv %f, srcValue
  // %rem = irem %f, srcValue
  // UseDef_0 = %quo
  // UseDef_1 = %rem

  // Logical Shift left DividendHighBytes by n-bits (where n is the size of
  // UseDefRegSize) to get the high bytes and set DefReg_1 to the resulting
  // value.
  // DoubleTy type is of type twice the use reg size
  Type *DoubleTy = Type::getIntNTy(Ctx, UseDefRegSize * 2);
  Value *ShiftAmountVal =
      ConstantInt::get(DoubleTy, UseDefRegSize, false /* isSigned */);
  // Cast DividendHighBytes and DividendLowBytes to types with double the
  // size.
  CastInst *DividendLowBytesDT = CastInst::Create(
      CastInst::getCastOpcode(DividendLowBytes, true, DoubleTy, true),
      DividendLowBytes, DoubleTy);
  RaisedBB->getInstList().push_back(DividendLowBytesDT);

  CastInst *DividendHighBytesDT = CastInst::Create(
      CastInst::getCastOpcode(DividendHighBytes, true, DoubleTy, true),
      DividendHighBytes, DoubleTy);
  RaisedBB->getInstList().push_back(DividendHighBytesDT);

  Instruction *LShlInst =
      BinaryOperator::CreateNUWShl(DividendHighBytesDT, ShiftAmountVal);
  RaisedBB->getInstList().push_back(LShlInst);

  // Combine the dividend values to get full dividend.
  // or instruction
  Instruction *FullDividend =
      BinaryOperator::CreateOr(LShlInst, DividendLowBytesDT);
  RaisedBB->getInstList().push_back(FullDividend);

  // If the srcValue is a stack allocation, load the value from the stack
  // slot
  if (isa<AllocaInst>(SrcValue)) {
    // Load the value from memory location
    LoadInst *loadInst = new LoadInst(SrcValue);
    unsigned int memAlignment =
        SrcValue->getType()->getPointerElementType()->getPrimitiveSizeInBits() /
        8;
    loadInst->setAlignment(MaybeAlign(memAlignment));
    RaisedBB->getInstList().push_back(loadInst);
    SrcValue = loadInst;
  }
  // Cast divisor (srcValue) to double type
  CastInst *srcValueDT =
      CastInst::Create(CastInst::getCastOpcode(SrcValue, true, DoubleTy, true),
                       SrcValue, DoubleTy);
  RaisedBB->getInstList().push_back(srcValueDT);

  // quotient
  Instruction *QuotientDT =
      BinaryOperator::CreateSDiv(FullDividend, srcValueDT);
  RaisedBB->getInstList().push_back(QuotientDT);

  // Cast Quotient back to UseDef reg value type
  CastInst *Quotient =
      CastInst::Create(CastInst::getCastOpcode(
                           QuotientDT, true, DividendLowBytes->getType(), true),
                       QuotientDT, DividendLowBytes->getType());

  RaisedBB->getInstList().push_back(Quotient);
  // Update ssa val of UseDefReg_0
  raisedValues->setPhysRegSSAValue(UseDefReg_0, MI.getParent()->getNumber(),
                                   Quotient);

  // remainder
  Instruction *RemainderDT =
      BinaryOperator::CreateSRem(FullDividend, srcValueDT);
  RaisedBB->getInstList().push_back(RemainderDT);

  // Cast RemainderDT back to UseDef reg value type
  CastInst *Remainder = CastInst::Create(
      CastInst::getCastOpcode(RemainderDT, true, DividendHighBytes->getType(),
                              true),
      RemainderDT, DividendHighBytes->getType());

  RaisedBB->getInstList().push_back(Remainder);
  // Update ssa val of UseDefReg_1
  raisedValues->setPhysRegSSAValue(UseDefReg_1, MI.getParent()->getNumber(),
                                   Remainder);

  return true;
}

// Raise compare instruction. If the the instruction is a memory compare, it
// is expected that this function is called from raiseMemRefMachineInstr
// after verifying the accessibility of memory location and with
// isMemCompare set true.If isMemCompare is true, memRefValue needs to be
// the non-null memory reference value representing the memory reference the
// instruction uses.

bool X86MachineInstructionRaiser::raiseCompareMachineInstr(
    const MachineInstr &MI, bool isMemCompare, Value *MemRefValue) {
  // Get index of memory reference in the instruction.
  int memoryRefOpIndex = getMemoryRefOpIndex(MI);
  int MBBNo = MI.getParent()->getNumber();
  unsigned int DestReg = X86::NoRegister;
  assert((((memoryRefOpIndex != -1) && isMemCompare) ||
          ((memoryRefOpIndex == -1) && !isMemCompare)) &&
         "Inconsistent memory reference operand information specified for "
         "compare instruction");
  MCInstrDesc MCIDesc = MI.getDesc();
  unsigned NumImplicitUses = MCIDesc.getNumImplicitUses();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Is this a sub instruction?
  bool isSUBInst = instrNameStartsWith(MI, "SUB");

  SmallVector<Value *, 2> OpValues = {nullptr, nullptr};

  // Get operand indices
  if (isMemCompare) {
    // This is a memory referencing instruction.
    Type *NonMemRefOpTy;
    const MachineOperand *NonMemRefOp;
    assert(memoryRefOpIndex >= 0 &&
           "Unexpected memory operand index in compare instruction");
    unsigned nonMemRefOpIndex =
        (memoryRefOpIndex == 0) ? X86::AddrNumOperands : 0;
    NonMemRefOp = &(MI.getOperand(nonMemRefOpIndex));
    if (NonMemRefOp->isReg()) {
      NonMemRefOpTy = getPhysRegOperandType(MI, nonMemRefOpIndex);
    } else if (NonMemRefOp->isImm()) {
      NonMemRefOpTy = getImmOperandType(MI, nonMemRefOpIndex);
    } else {
      MI.dump();
      assert(false && "Unhandled second operand type in compare instruction");
    }

    assert(MemRefValue != nullptr && "Null memory reference value encountered "
                                     "while raising compare instruction");
    // Convert it to a pointer of type of non-memory operand
    if (isEffectiveAddrValue(MemRefValue)) {
      PointerType *PtrTy = PointerType::get(NonMemRefOpTy, 0);
      IntToPtrInst *convIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(convIntToPtr);
      MemRefValue = convIntToPtr;
    }
    // Load the value from memory location
    LoadInst *loadInst = new LoadInst(MemRefValue);
    loadInst->setAlignment(MaybeAlign(
        MemRefValue->getPointerAlignment(MR->getModule()->getDataLayout())));
    RaisedBB->getInstList().push_back(loadInst);
    // save it at the appropriate index of operand value array
    if (memoryRefOpIndex == 0) {
      OpValues[0] = loadInst;
    } else {
      OpValues[1] = loadInst;
    }

    // Get value for non-memory operand of compare.
    Value *NonMemRefVal = nullptr;
    if (NonMemRefOp->isReg()) {
      NonMemRefVal = getRegOrArgValue(NonMemRefOp->getReg(), MBBNo);
    } else if (NonMemRefOp->isImm()) {
      NonMemRefVal =
          ConstantInt::get(MemRefValue->getType()->getPointerElementType(),
                           NonMemRefOp->getImm());
    } else {
      MI.dump();
      assert(false && "Unhandled first operand type in compare instruction");
    }
    // save non-memory reference value at the appropriate index of operand
    // value array
    if (memoryRefOpIndex == 0) {
      OpValues[1] = NonMemRefVal;
    } else {
      OpValues[0] = NonMemRefVal;
    }
  } else {
    // The instruction operands do not reference memory
    unsigned Op1Index, Op2Index;

    // Determine the appropriate operand indices of the instruction based on the
    // usage of implicit registers. Note that a cmp instruction is translated as
    // sub op1, op2 (i.e., op1 - op2).
    if (NumImplicitUses == 1) {
      // If an implicit operand is used, that is op1.
      MCPhysReg UseReg = MCIDesc.ImplicitUses[0];
      Op1Index = MI.findRegisterUseOperandIdx(UseReg, false, nullptr);
      Op2Index = MCIDesc.getNumDefs() == 0 ? 0 : 1;
    } else {
      // Explicit operands are used
      Op1Index = MCIDesc.getNumDefs() == 0 ? 0 : 1;
      Op2Index = Op1Index + 1;
    }

    MachineOperand CmpOp1 = MI.getOperand(Op1Index);
    MachineOperand CmpOp2 = MI.getOperand(Op2Index);

    assert((CmpOp1.isReg() || CmpOp1.isImm()) &&
           "Unhandled first operand type in compare instruction");

    assert((CmpOp2.isReg() || CmpOp2.isImm()) &&
           "Unhandled second operand type in compare instruction");

    if (CmpOp1.isReg()) {
      OpValues[0] =
          getRegOrArgValue(CmpOp1.getReg(), MI.getParent()->getNumber());
    }

    if (CmpOp2.isReg()) {
      OpValues[1] =
          getRegOrArgValue(CmpOp2.getReg(), MI.getParent()->getNumber());
    }

    // Construct value if either of the operands is an immediate
    if (CmpOp1.isImm()) {
      assert((OpValues[1] != nullptr) &&
             "At least one value expected while raising compare instruction");
      OpValues[0] = ConstantInt::get(OpValues[1]->getType(), CmpOp1.getImm());
    }

    if (CmpOp2.isImm()) {
      assert((OpValues[0] != nullptr) &&
             "At least one value expected while raising compare instruction");
      OpValues[1] = ConstantInt::get(OpValues[0]->getType(), CmpOp2.getImm());
    }
  }
  assert(OpValues[0] != nullptr && OpValues[1] != nullptr &&
         "Unable to materialize compare operand values");

  // If the first operand is register, make sure the source operand value types
  // are the same as destination register type.
  if (MI.getOperand(0).isReg()) {
    DestReg = MI.getOperand(0).getReg();
    if (DestReg != X86::NoRegister) {
      Type *DestTy = getPhysRegOperandType(MI, 0);
      for (int i = 0; i < 2; i++) {
        if (OpValues[i]->getType() != DestTy) {
          CastInst *CInst = CastInst::Create(
              CastInst::getCastOpcode(OpValues[i], false, DestTy, false),
              OpValues[i], DestTy);
          RaisedBB->getInstList().push_back(CInst);
          OpValues[i] = CInst;
        }
      }
    }
  }

  // If the number of implicit use operand is one, make sure the source operand
  // value type is the same as the implicit use operand value type.
  if (NumImplicitUses == 1) {
    if (OpValues[0]->getType() != OpValues[1]->getType()) {
      CastInst *CInst = CastInst::Create(
          CastInst::getCastOpcode(OpValues[0], false, OpValues[1]->getType(),
                                  false),
          OpValues[0], OpValues[1]->getType());
      RaisedBB->getInstList().push_back(CInst);
      OpValues[0] = CInst;
    }
  }

  assert((OpValues[0]->getType() == OpValues[1]->getType()) &&
         "Mis-matched operand types encountered while raising compare "
         "instruction");

  raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
  raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
  // SubInst is of type Value * to allow for a potential need to pass it to
  // castValue(), if needed.
  Value *SubInst = BinaryOperator::CreateSub(OpValues[0], OpValues[1]);
  // Casting SubInst to instruction to be added to the raised basic block is
  // correct since it is known to be specifically of type Instruction.
  RaisedBB->getInstList().push_back(dyn_cast<Instruction>(SubInst));

  if (isSUBInst) {
    switch (MI.getOpcode()) {
    case X86::SUB8mi:
    case X86::SUB8mi8:
    case X86::SUB8mr:
    case X86::SUB16mi:
    case X86::SUB16mi8:
    case X86::SUB16mr:
    case X86::SUB32mi:
    case X86::SUB32mi8:
    case X86::SUB32mr:
    case X86::SUB64mi8:
    case X86::SUB64mi32:
    case X86::SUB64mr: {
      // This instruction moves a source value to memory. So, if the types of
      // the source value and that of the memory pointer content are not the
      // same, it is the source value that needs to be cast to match the type of
      // destination (i.e., memory). It needs to be sign extended as needed.
      Type *MatchTy = MemRefValue->getType()->getPointerElementType();
      if (!MatchTy->isArrayTy()) {
        SubInst = castValue(SubInst, MatchTy, RaisedBB);
      }

      // Store SubInst to MemRefValue only if this is a sub MI or MR
      // instruction. Do not update if this is a cmp instruction.
      StoreInst *StInst = new StoreInst(SubInst, MemRefValue);
      RaisedBB->getInstList().push_back(StInst);
    } break;
    case X86::SUB32rr:
    case X86::SUB64rr:
    case X86::SUB8rm:
    case X86::SUB32rm:
    case X86::SUB64rm: {
      assert(MCIDesc.getNumDefs() == 1 &&
             "Unexpected number of def operands of sub instruction");
      // Update the DestReg only if this is a sub instruction. Do not update
      // if this is a cmp instruction
      raisedValues->setPhysRegSSAValue(DestReg, MI.getParent()->getNumber(),
                                       SubInst);
    } break;
    default:
      assert(false && "Unhandled sub instruction found");
    }
  }
  // Now update EFLAGS
  assert(MCIDesc.getNumImplicitDefs() == 1 &&
         "Compare instruction does not have exactly one implicit def");
  MCPhysReg ImpDefReg = MCIDesc.ImplicitDefs[0];
  assert(ImpDefReg == X86::EFLAGS &&
         "Expected implicit EFLAGS def in compare instruction");
  // Create instructions to set CF, ZF, SF, and OF flags according to the result
  // SubInst.
  // NOTE: Support for tracking AF and PF not yet implemented.
  raisedValues->testAndSetEflagSSAValue(EFLAGS::CF, MI, SubInst);
  raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI, SubInst);
  raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI, SubInst);
  raisedValues->testAndSetEflagSSAValue(EFLAGS::OF, MI, SubInst);
  return true;
}

// Raise a load/store instruction.
// Current implementation only raises instructions that load and store to
// stack.
bool X86MachineInstructionRaiser::raiseMemRefMachineInstr(
    const MachineInstr &MI) {

  // Handle the push instruction that is marked as a memory store
  // instruction
  if (isPushToStack(MI)) {
    return raisePushInstruction(MI);
  }

  if (isPopFromStack(MI)) {
    return raisePopInstruction(MI);
  }

  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();

  int LoadOrStoreOpIndex = -1;

  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  // Should have found the index of the memory reference operand
  assert(MemoryRefOpIndex != -1 && "Unable to find memory reference "
                                   "operand of a load/store instruction");
  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);

  // Get the operand whose value is stored to memory or that is loaded from
  // memory.

  if (MIDesc.mayStore()) {
    // If the instruction stores to stack, find the register whose value is
    // being stored. It would be the operand at offset
    // memRefOperandStartIndex + X86::AddrNumOperands
    LoadOrStoreOpIndex = MemoryRefOpIndex + X86::AddrNumOperands;
  } else if (MIDesc.mayLoad()) {
    // If the instruction loads to memory to a register, it has 1 def.
    // Operand 0 is the loadOrStoreOp.
    assert(((MIDesc.getNumDefs() == 0) || (MIDesc.getNumDefs() == 1)) &&
           "Instruction that loads from memory expected to have only "
           "one target");
    if (MIDesc.getNumDefs() == 1) {
      LoadOrStoreOpIndex = 0;
      assert(MI.getOperand(LoadOrStoreOpIndex).isReg() &&
             "Target of instruction that loads from "
             "memory expected to be a register");
    } else if (!MIDesc.isCompare()) {
      switch (getInstructionKind(Opcode)) {
      case InstructionKind::DIVIDE_MEM_OP:
      case InstructionKind::LOAD_FPU_REG:
        break;
      default:
        MI.print(errs());
        assert(false && "Encountered unhandled memory load instruction");
      }
    }
  } else {
    MI.print(errs());
    assert(false && "Encountered unhandled instruction that is not load/store");
  }

  Value *MemoryRefValue = nullptr;

  if (MemRef.BaseType == X86AddressMode::RegBase) {
    // If it is a stack reference, allocate a stack slot in case the current
    // memory reference is new. Else get the stack reference using the
    // stackslot index of the previously known stack ref.

    uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
    if (BaseSupReg == x86RegisterInfo->getStackRegister() ||
        BaseSupReg == x86RegisterInfo->getFramePtr()) {
      MemoryRefValue = getStackAllocatedValue(MI, MemRef, false);
    }
    // Handle PC-relative addressing.

    // NOTE: This tool now raises only shared libraries and executables -
    // NOT object files. So, instructions with 0 register (which typically
    // are seen in a relocatable object file for the linker to patch) are
    // not expected to be encountered.
    else if (BaseSupReg == X86::RIP) {
      MemoryRefValue = createPCRelativeAccesssValue(MI);
    }
    // If this is neither a stack reference nor a pc-relative access, get the
    // associated memory address expression value.
    if (MemoryRefValue == nullptr) {
      Value *memrefValue = getMemoryAddressExprValue(MI);
      MemoryRefValue = memrefValue;
    }
  } else {
    // TODO : Memory references with BaseType FrameIndexBase
    // (i.e., not RegBase type)
    outs() << "****** Unhandled memory reference in instruction\n\t";
    MI.dump();
    outs() << "****** reference of type FrameIndexBase";
    return false;
  }

  assert(MemoryRefValue != nullptr &&
         "Unable to construct memory referencing value");

  // Raise a memory compare instruction
  if (MI.isCompare()) {
    return raiseCompareMachineInstr(MI, true /* isMemRef */, MemoryRefValue);
  }

  // Now that we have all necessary information about memory reference and
  // the load/store operand, we can raise the memory referencing instruction
  // according to the opcode.
  bool success = false;
  switch (getInstructionKind(Opcode)) {
    // Move register or immediate to memory
  case InstructionKind::MOV_TO_MEM: {
    success = raiseMoveToMemInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::INPLACE_MEM_OP:
    success = raiseInplaceMemOpInstr(MI, MemoryRefValue);
    break;
  // Move register from memory
  case InstructionKind::MOV_FROM_MEM: {
    success = raiseMoveFromMemInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::BINARY_OP_RM: {
    success = raiseBinaryOpMemToRegInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::DIVIDE_MEM_OP: {
    success = raiseDivideInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::LOAD_FPU_REG:
    success = raiseLoadIntToFloatRegInstr(MI, MemoryRefValue);
    break;
  case InstructionKind::STORE_FPU_REG:
    success = raiseStoreIntToFloatRegInstr(MI, MemoryRefValue);
    break;
  default:
    outs() << "Unhandled memory referencing instruction.\n";
    MI.dump();
  }
  return success;
}

bool X86MachineInstructionRaiser::raiseSetCCMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  int MBBNo = MI.getParent()->getNumber();
  LLVMContext &Ctx(MF.getFunction().getContext());
  Value *FalseValue = ConstantInt::getFalse(Ctx);
  Value *TrueValue = ConstantInt::getTrue(Ctx);
  bool Success = false;

  assert(MIDesc.getNumDefs() == 1 &&
         "Not found expected one destination operand of set instruction");
  assert(MIDesc.getNumImplicitUses() == 1 &&
         MIDesc.hasImplicitUseOfPhysReg(X86::EFLAGS) &&
         "Not found expected implicit use of eflags in set instruction.");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
  const MachineOperand &DestOp = MI.getOperand(0);

  CmpInst::Predicate Pred = CmpInst::Predicate::BAD_ICMP_PREDICATE;
  switch (X86::getCondFromSETCC(MI)) {
  case X86::COND_NE: {
    // Check if ZF == 0
    Pred = CmpInst::Predicate::ICMP_EQ;
    Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
    CmpInst *CMP = new ICmpInst(Pred, ZFValue, FalseValue);
    RaisedBB->getInstList().push_back(CMP);
    raisedValues->setPhysRegSSAValue(DestOp.getReg(),
                                     MI.getParent()->getNumber(), CMP);
    Success = true;
  } break;
  case X86::COND_E: {
    // Check if ZF == 1
    Pred = CmpInst::Predicate::ICMP_EQ;
    Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
    CmpInst *CMP = new ICmpInst(Pred, ZFValue, TrueValue);
    RaisedBB->getInstList().push_back(CMP);
    raisedValues->setPhysRegSSAValue(DestOp.getReg(),
                                     MI.getParent()->getNumber(), CMP);
    Success = true;
  } break;
  case X86::COND_G: {
    // Check ZF == 0 and SF == OF
    Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
    Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
    Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
    assert((ZFValue != nullptr) && (SFValue != nullptr) &&
           (OFValue != nullptr) &&
           "Failed to get EFLAGS value while raising CMOVG!");
    Pred = CmpInst::Predicate::ICMP_EQ;

    // Compare ZF and 0
    CmpInst *ZFCond = new ICmpInst(Pred, ZFValue, FalseValue, "ZFCmp_CMOVG");
    RaisedBB->getInstList().push_back(ZFCond);

    // Test SF == OF
    CmpInst *SFOFCond = new ICmpInst(Pred, SFValue, OFValue, "SFOFCmp_CMOVG");
    RaisedBB->getInstList().push_back(SFOFCond);
    Instruction *CMOVCond =
        BinaryOperator::CreateAnd(ZFCond, SFOFCond, "Cond_CMOVG");
    RaisedBB->getInstList().push_back(CMOVCond);
    raisedValues->setPhysRegSSAValue(DestOp.getReg(),
                                     MI.getParent()->getNumber(), CMOVCond);
    Success = true;
  } break;
  case X86::COND_INVALID:
    assert(false && "Set instruction with invalid condition found");
    break;
  default:
    assert(false && "Set instruction with unhandled condition found");
    break;
  }

  if (Pred == CmpInst::Predicate::BAD_ICMP_PREDICATE) {
    MI.dump();
    assert(false && "Unhandled set instruction");
  }
  return Success;
}

// Raise a binary operation instruction with operand encoding MRI or MRC
// TODO: The current implementation handles only instructions with first operand
// as register operand. Need to expand to add support for instructions with
// first operand as memory operand.
bool X86MachineInstructionRaiser::raiseBinaryOpMRIOrMRCEncodedMachineInstr(
    const MachineInstr &MI) {
  bool success = true;
  unsigned int DstIndex = 0, SrcOp1Index = 1, SrcOp2Index = 2, SrcOp3Index = 3;
  const MCInstrDesc &MIDesc = MI.getDesc();

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // A binary operation instruction with encoding MRI or MRC specifies three
  // operands - the first operand is memory or register and the second is a
  // register and the third is an immediate value or CL register. As noted
  // above, support is not yet implemented if for first operand being a memory
  // operand.
  //
  // X86::EFLAGS is the implicit def operand.
  unsigned NumOperands = MI.getNumExplicitOperands() +
                         MIDesc.getNumImplicitUses() +
                         MIDesc.getNumImplicitDefs();

  assert((NumOperands == 5) && "Unexpected number of operands of BinOp "
                               "instruction with MRI/MRC operand format");

  // Ensure that the instruction defines EFLAGS as implicit define register.
  assert(MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
         "Expected implicit def operand EFLAGS not found");

  // TODO: Memory accessing instructions not yet supported.
  assert(!MIDesc.mayLoad() && !MIDesc.mayStore() &&
         "Unsupported MRI/MRC instruction");

  MachineOperand DstOp = MI.getOperand(DstIndex);
  MachineOperand SrcOp1 = MI.getOperand(SrcOp1Index);
  MachineOperand SrcOp2 = MI.getOperand(SrcOp2Index);
  // Check the validity of operands.
  // The first operand is also as the destination operand.
  // Verify source and dest are tied and are registers.
  assert(DstOp.isTied() && (MI.findTiedOperandIdx(DstIndex) == SrcOp1Index) &&
         "Expect tied operand in MRI/MRC encoded instruction");
  assert(SrcOp1.isReg() && SrcOp2.isReg() &&
         "Unexpected operands of an MRC/MRI encoded instruction");
  // Values need to be discovered to form the appropriate instruction.
  // Note that DstOp is both source and dest.
  unsigned int DstPReg = DstOp.getReg();
  Value *SrcOp1Value = matchSSAValueToSrcRegSize(MI, SrcOp1.getReg());
  Value *SrcOp2Value = matchSSAValueToSrcRegSize(MI, SrcOp2.getReg());
  assert(SrcOp1Value->getType() == SrcOp2Value->getType() &&
         "Mismatched types of MRI/MRC encoded instructions");
  Instruction *BinOpInstr = nullptr;
  // EFLAGS that are affected by the result of the binary operation
  std::vector<unsigned> AffectedEFlags;
  Value *CountValue = nullptr;

  switch (MI.getOpcode()) {
  case X86::SHLD16rri8:
  case X86::SHLD32rri8:
  case X86::SHLD64rri8:
  case X86::SHRD16rri8:
  case X86::SHRD32rri8:
  case X86::SHRD64rri8: {
    MachineOperand SrcOp3 = MI.getOperand(SrcOp3Index);
    assert(SrcOp3.isImm() &&
           "Expect immediate operand in an MRI encoded instruction");
    CountValue =
        ConstantInt::get(getImmOperandType(MI, SrcOp3Index), SrcOp3.getImm());
    // cast CountValue as needed
    CountValue = castValue(CountValue, SrcOp1Value->getType(), RaisedBB);
  } break;
  case X86::SHLD16rrCL:
  case X86::SHLD32rrCL:
  case X86::SHLD64rrCL:
  case X86::SHRD16rrCL:
  case X86::SHRD32rrCL:
  case X86::SHRD64rrCL: {
    assert((MIDesc.getNumImplicitUses() == 1) &&
           "Expect one implicit use in MCR encoded instruction");
    assert((MIDesc.ImplicitUses[0] == X86::CL) &&
           "Expect implicit CL regsiter operand in MCR encoded instruction");
    CountValue = matchSSAValueToSrcRegSize(MI, X86::CL);
    // cast CountValue as needed
    CountValue = castValue(CountValue, SrcOp1Value->getType(), RaisedBB);
  } break;
  default:
    llvm_unreachable("Unhandled MRI/MRC encoded instruction");
  }

  // Now generate the call to instrinsic
  // Types of all operands are already asserted to be the same
  auto IntrinsicKind = Intrinsic::not_intrinsic;
  if (instrNameStartsWith(MI, "SHLD")) {
    IntrinsicKind = Intrinsic::fshl;
  } else if (instrNameStartsWith(MI, "SHRD")) {
    IntrinsicKind = Intrinsic::fshr;
    // Swap the argument order
    Value *tmp = SrcOp1Value;
    SrcOp1Value = SrcOp2Value;
    SrcOp2Value = tmp;
  } else
    llvm_unreachable("Unhandled MCR/MCI encoded instruction");
  assert((IntrinsicKind != Intrinsic::not_intrinsic) &&
         "Failed to set appropriate intrinsic kind");
  Module *M = MR->getModule();
  Function *IntrinsicFunc =
      Intrinsic::getDeclaration(M, IntrinsicKind, SrcOp1Value->getType());
  Value *IntrinsicCallArgs[] = {SrcOp1Value, SrcOp2Value, CountValue};
  BinOpInstr =
      CallInst::Create(IntrinsicFunc, ArrayRef<Value *>(IntrinsicCallArgs));
  // Test an set EFLAGs
  AffectedEFlags.push_back(EFLAGS::CF);
  // Insert the binary operation instruction
  RaisedBB->getInstList().push_back(BinOpInstr);
  // Test and set affected flags
  for (auto Flag : AffectedEFlags)
    raisedValues->testAndSetEflagSSAValue(Flag, MI, BinOpInstr);

  // Update PhysReg to Value map
  if (DstPReg != X86::NoRegister)
    raisedValues->setPhysRegSSAValue(DstPReg, MI.getParent()->getNumber(),
                                     BinOpInstr);
  return success;
}

// Raise a binary operation instruction with operand encoding I or RI
bool X86MachineInstructionRaiser::raiseBinaryOpImmToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int DstIndex = 0, SrcOp1Index = 1, SrcOp2Index = 2;
  const MCInstrDesc &MIDesc = MI.getDesc();
  int MBBNo = MI.getParent()->getNumber();

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // A binary operation instruction with encoding I specifies one operand -
  // using AL/AX/EAX/RAX as implicit register operand.
  // A binary operation instruction with encoding RI specifies two operands
  // - the first operand is a register and the second the immediate value
  //
  // The first operand is also as the destination operand.
  // X86::EFLAGS is the implicit def operand.
  unsigned NumOperands = MI.getNumExplicitOperands() +
                         MIDesc.getNumImplicitUses() +
                         MIDesc.getNumImplicitDefs();
  assert(((NumOperands == 3) || (NumOperands == 4)) &&
         "Unexpected number of operands of BinOp instruction with RI/I "
         "operand format");

  // Create a stack alloc slot corresponding to the adjusted sp value, if the
  // operands reference SP.
  if ((MIDesc.getNumDefs() == 1) &&
      (find64BitSuperReg(MI.getOperand(DstIndex).getReg()) == X86::RSP) &&
      (find64BitSuperReg(MI.getOperand(SrcOp1Index).getReg()) == X86::RSP) &&
      MI.getOperand(SrcOp2Index).isImm() &&
      MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS)) {

    // Find the stack allocation, if any, associated with the stack index
    // being changed to.
    X86AddressMode AdjSPRef;
    AdjSPRef.Base.Reg = X86::RSP;
    uint64_t Imm = MI.getOperand(SrcOp2Index).getImm();

    switch (MI.getOpcode()) {
    case X86::ADD8i8:
    case X86::ADD16i16:
    case X86::ADD32i32:
    case X86::ADD64i32:
    case X86::ADD8ri:
    case X86::ADD16ri:
    case X86::ADD16ri8:
    case X86::ADD32ri:
    case X86::ADD32ri8:
    case X86::ADD64ri8:
    case X86::ADD64ri32:
      AdjSPRef.Disp = Imm;
      break;
    case X86::SUB32ri:
    case X86::SUB32ri8:
    case X86::SUB64ri8:
    case X86::SUB64ri32:
    case X86::SUB64i32:
      AdjSPRef.Disp = -Imm;
      break;
    default:
      assert(false && "SP computation - unhandled binary opcode instruction");
    }

    Value *StackRefVal = getStackAllocatedValue(MI, AdjSPRef, true);
    assert((StackRefVal != nullptr) && "Reference to unallocated stack slot");
    raisedValues->setPhysRegSSAValue(X86::RSP, MI.getParent()->getNumber(),
                                     StackRefVal);
  } else {
    // Values need to be discovered to form the appropriate instruction.
    Value *SrcOp1Value = nullptr;
    Value *SrcOp2Value = nullptr;
    unsigned int DstPReg = X86::NoRegister;

    // Ensure that the instruction defines EFLAGS as implicit define register.
    assert(MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Expected implicit def operand EFLAGS not found");

    // A vector holding source operand values.
    SmallVector<Value *, 2> OpValues = {nullptr, nullptr};
    unsigned NumImplicitDefs = MIDesc.getNumImplicitDefs();
    assert(((NumImplicitDefs == 1) || (NumImplicitDefs == 2)) &&
           "Encountered instruction unexpected number of implicit defs");
    // Index of the instruction operand being read.
    unsigned CurExplicitOpIndex = 0;
    // Keep a count of the number of instruction operands evaluated. A count of
    // NumOperands need to be evaluated. The value is 1 because we have already
    // checked that EFLAGS is an implicit def.
    unsigned NumOperandsEval = 1;
    // Find destination register of the instruction
    // If the instruction has an explicit dest operand, get the DstPreg from
    // dest operand.
    if (MIDesc.getNumDefs() != 0) {
      // Get destination reg
      const MachineOperand &DstOp = MI.getOperand(CurExplicitOpIndex);
      assert(DstOp.isReg() && "Not found expected register to be the "
                              "destination operand of BinOp instruction with "
                              "RI/I operand format");
      DstPReg = DstOp.getReg();
      // Go to next explicit operand index
      CurExplicitOpIndex++;
      // Increment the number of operands evaluated
      NumOperandsEval++;
    }
    // If there is no explicit dst register in the instruction, find if there is
    // an implicit physical register defined by the instruction.
    if ((NumImplicitDefs == 2) && (DstPReg == X86::NoRegister)) {
      // Find the implicit dest reg. Register at index 0 is the implicit def
      // physical register. That at index 1 is EFLAGS.
      DstPReg = MIDesc.ImplicitDefs[0];
      assert(((DstPReg == X86::AL) || (DstPReg == X86::AX) ||
              (DstPReg == X86::EAX) || (DstPReg == X86::RAX)) &&
             "Expected implicit use of operand AL/AX/EAX/RAX not found");
      // Increment the number of operands evaluated
      NumOperandsEval++;
    }

    // Now, find source operand values.
    // First check if there are any implicit use operands of the instruction.
    unsigned NumImplicitUses = MIDesc.getNumImplicitUses();
    assert((NumImplicitUses < 3) &&
           "More than two implicit use operands found in BinOp instruction "
           "with RI/I format operands");
    unsigned SrcValIdx = 0;
    for (; SrcValIdx < NumImplicitUses; SrcValIdx++) {
      OpValues[SrcValIdx] =
          matchSSAValueToSrcRegSize(MI, MIDesc.ImplicitUses[SrcValIdx]);
      NumOperandsEval++;
    }

    // Get the explicit source operand values.
    while (NumOperandsEval < NumOperands) {
      assert((SrcValIdx < 2) && "Unexpected operand index while raising BinOp "
                                "instruction with RI/I operand format");
      const MachineOperand &SrcOp = MI.getOperand(CurExplicitOpIndex);
      if (SrcValIdx == 0) {
        assert(SrcOp.isReg() &&
               "Not found expected register to be the first "
               "operand of BinOp instruction with RI/I operand format");

        // Get value of SrcOp appropriately sized.
        MachineOperand MO = MI.getOperand(CurExplicitOpIndex);
        assert(MO.isReg() && "Unexpected non-register operand");
        OpValues[0] = matchSSAValueToSrcRegSize(MI, MO.getReg());

        CurExplicitOpIndex++;
        NumOperandsEval++;
      }

      // Get the second source operand value if the instruction has at least two
      // operands.
      if (SrcValIdx == 1) {
        // If the instruction has an explicit second operand
        // Get value of SrcOp
        assert(SrcOp.isImm() && "Expect immediate operand in a BinOp "
                                "instruction with RI/I operand format");
        assert(OpValues[0] != nullptr &&
               "Undefined first source value encountered in BinOp instruction "
               "with RI/I operand format");
        // Create constant of type that matches that of the dest register
        // If the instruction has no dest operand (such as TEST) set the type of
        // immediate value to be that of first operand value.
        Type *Ty = (DstPReg == X86::NoRegister) ? OpValues[0]->getType()
                                                : getPhysRegType(DstPReg);
        OpValues[1] = ConstantInt::get(Ty, SrcOp.getImm());
        CurExplicitOpIndex++;
        NumOperandsEval++;
      }
      SrcValIdx++;
    }

    assert((NumOperandsEval == NumOperands) &&
           "Failed to evaluate operands of BinOp instruction correctly");

    // Set up the source values to be used by BinOp instruction.

    SrcOp1Value = OpValues[0];
    SrcOp2Value = OpValues[1];

    // Check validity of source operand values. Both source operands need to be
    // non null values. The only exception is when the instruction has 3
    // operands indicating that there is an implicit constant value encoded by
    // the instruction such as SHR81. Such operands are constructed in an
    // instruction-specific way before the generating the appropriate IR
    // instruction.
    assert((SrcOp1Value != nullptr) &&
           ((SrcOp2Value != nullptr) ||
            ((NumOperands == 3) && (SrcOp2Value == nullptr))) &&
           "Unexpected source values encountered in BinOp instruction with "
           "RI/I operand format");

    Instruction *BinOpInstr = nullptr;
    // EFLAGS that are affected by the result of the binary operation
    std::vector<unsigned> AffectedEFlags;

    switch (MI.getOpcode()) {
    case X86::ADD8i8:
    case X86::ADD16i16:
    case X86::ADD8ri:
    case X86::ADD16ri:
    case X86::ADD16ri8:
    case X86::ADD32ri:
    case X86::ADD32ri8:
    case X86::ADD32i32:
    case X86::ADD64ri8:
    case X86::ADD64ri32:
    case X86::ADD64i32: {
      // Generate add instruction
      BinOpInstr = BinaryOperator::CreateAdd(SrcOp1Value, SrcOp2Value);
      // Clear OF and CF
      raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
      AffectedEFlags.push_back(EFLAGS::CF);
      // Test and set of OF not yet supported
    } break;
    case X86::SUB32ri:
    case X86::SUB32ri8:
    case X86::SUB64ri8:
    case X86::SUB64ri32:
    case X86::SUB64i32:
      // Generate sub instruction
      BinOpInstr = BinaryOperator::CreateSub(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      AffectedEFlags.push_back(EFLAGS::CF);
      break;
    case X86::AND8i8:
    case X86::AND8ri:
    case X86::AND16i16:
    case X86::AND16ri:
    case X86::AND16ri8:
    case X86::AND32i32:
    case X86::AND32ri:
    case X86::AND32ri8:
    case X86::AND64i32:
    case X86::AND64ri8:
    case X86::AND64ri32:
      // Generate and instruction
      BinOpInstr = BinaryOperator::CreateAnd(SrcOp1Value, SrcOp2Value);
      // Clear OF and CF
      raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
      // Test an set EFLAGs
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      // Test and set of PF not yet supported
      break;
    case X86::OR8i8:
    case X86::OR8ri:
    case X86::OR16ri8:
    case X86::OR16i16:
    case X86::OR16ri:
    case X86::OR32i32:
    case X86::OR32ri:
    case X86::OR32ri8:
    case X86::OR64i32:
    case X86::OR64ri32:
    case X86::OR64ri8:
      // Generate or instruction
      BinOpInstr = BinaryOperator::CreateOr(SrcOp1Value, SrcOp2Value);
      // Clear OF and CF
      raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
      // Test an set EFLAGs
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      // Test and set of PF not yet supported
      break;
    case X86::XOR8ri:
    case X86::XOR16ri:
    case X86::XOR32ri:
    case X86::XOR8i8:
    case X86::XOR16i16:
    case X86::XOR32i32:
      // Generate xor instruction
      BinOpInstr = BinaryOperator::CreateXor(SrcOp1Value, SrcOp2Value);
      // Clear OF and CF
      raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
      // Test an set EFLAGs
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      // Test and set of PF not yet supported
      break;
    case X86::IMUL32rri8:
    case X86::IMUL64rri8:
    case X86::IMUL64rri32:
      BinOpInstr = BinaryOperator::CreateMul(SrcOp1Value, SrcOp2Value);
      // TODO: Set affected EFLAGS information appropriately
      break;
    case X86::SHR8r1:
    case X86::SHR16r1:
    case X86::SHR32r1:
    case X86::SHR64r1:
      SrcOp2Value = ConstantInt::get(SrcOp1Value->getType(), 1);
      LLVM_FALLTHROUGH;
    case X86::SHR8ri:
    case X86::SHR16ri:
    case X86::SHR32ri:
    case X86::SHR64ri:
      // Generate shr instruction
      BinOpInstr = BinaryOperator::CreateLShr(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    case X86::SHL8ri:
    case X86::SHL16ri:
    case X86::SHL32ri:
    case X86::SHL64ri:
      // Generate shl instruction
      BinOpInstr = BinaryOperator::CreateShl(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    case X86::SAR8ri:
    case X86::SAR16ri:
    case X86::SAR32ri:
    case X86::SAR64ri:
      // Generate shr instruction
      BinOpInstr = BinaryOperator::CreateLShr(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    case X86::TEST8i8:
    case X86::TEST16i16:
    case X86::TEST32i32:
    case X86::TEST64i32:
    case X86::TEST8ri:
    case X86::TEST16ri:
    case X86::TEST32ri:
      BinOpInstr = BinaryOperator::CreateAnd(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    case X86::INC8r:
    case X86::INC16r:
    case X86::INC16r_alt:
    case X86::INC32r:
    case X86::INC32r_alt:
    case X86::INC64r:
      SrcOp2Value = ConstantInt::get(SrcOp1Value->getType(), 1);
      BinOpInstr = BinaryOperator::CreateAdd(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    case X86::DEC8r:
    case X86::DEC16r:
    case X86::DEC16r_alt:
    case X86::DEC32r:
    case X86::DEC32r_alt:
    case X86::DEC64r:
      SrcOp2Value = ConstantInt::get(SrcOp1Value->getType(), 1);
      BinOpInstr = BinaryOperator::CreateSub(SrcOp1Value, SrcOp2Value);
      AffectedEFlags.push_back(EFLAGS::SF);
      AffectedEFlags.push_back(EFLAGS::ZF);
      break;
    default:
      MI.dump();
      assert(false && "Unhandled reg to imm binary operator instruction");
      break;
    }

    // Insert the binary operation instruction
    RaisedBB->getInstList().push_back(BinOpInstr);
    // Test and set affected flags
    for (auto Flag : AffectedEFlags)
      raisedValues->testAndSetEflagSSAValue(Flag, MI, BinOpInstr);

    // Update PhysReg to Value map
    if (DstPReg != X86::NoRegister)
      raisedValues->setPhysRegSSAValue(DstPReg, MI.getParent()->getNumber(),
                                       BinOpInstr);
  }
  return true;
}

// Raise indirect branch instruction.
bool X86MachineInstructionRaiser::raiseIndirectBranchMachineInstr(
    ControlTransferInfo *CTRec) {
  const MachineInstr *MI = CTRec->CandidateMachineInstr;
  BasicBlock *CandBB = CTRec->CandidateBlock;

  const MCInstrDesc &MCID = MI->getDesc();

  // Make sure this function was called on a direct branch instruction.
  assert((MCID.TSFlags & X86II::ImmMask) == 0 &&
         "PC-Relative control transfer not expected");

  // Raise indirect branch instruction to jump table
  if (MI->getOperand(0).isJTI()) {
    unsigned jtIndex = MI->getOperand(0).getIndex();
    std::vector<JumpTableBlock> JTCases;
    const MachineJumpTableInfo *MJT = MF.getJumpTableInfo();

    // Get the case value
    MachineBasicBlock *cdMBB = jtList[jtIndex].conditionMBB;
    Value *cdi = getSwitchCompareValue(*cdMBB);
    assert(cdi != nullptr && "Failed to get switch compare value.");
    Type *caseValTy = cdi->getType();

    std::vector<MachineJumpTableEntry> JumpTables = MJT->getJumpTables();
    for (unsigned j = 0, f = JumpTables[jtIndex].MBBs.size(); j != f; ++j) {
      ConstantInt *CaseVal =
          cast<ConstantInt>(ConstantInt::get(caseValTy, j, true));
      MachineBasicBlock *Succ = JumpTables[jtIndex].MBBs[j];
      JTCases.push_back(std::make_pair(CaseVal, Succ));
    }

    // Create the Switch Instruction
    unsigned int numCases = JTCases.size();
    auto intr_df = mbbToBBMap.find(jtList[jtIndex].df_MBB->getNumber());

    BasicBlock *df_bb = intr_df->second;
    SwitchInst *Inst = SwitchInst::Create(cdi, df_bb, numCases);

    for (unsigned i = 0, e = numCases; i != e; ++i) {
      MachineBasicBlock *Mbb = JTCases[i].second;
      auto intr = mbbToBBMap.find(Mbb->getNumber());
      BasicBlock *bb = intr->second;
      Inst->addCase(JTCases[i].first, bb);
    }

    CandBB->getInstList().push_back(Inst);
    CTRec->Raised = true;
  } else {
    assert(false && "Support to raise indirect branches to non-jumptable "
                    "location not yet implemented");
  }
  return true;
}

// Raise direct branch instruction.
bool X86MachineInstructionRaiser::raiseDirectBranchMachineInstr(
    ControlTransferInfo *CTRec) {
  const MachineInstr *MI = CTRec->CandidateMachineInstr;
  BasicBlock *CandBB = CTRec->CandidateBlock;

  const MCInstrDesc &MCID = MI->getDesc();

  // Make sure this function was called on a direct branch instruction.
  assert(X86II::isImmPCRel(MCID.TSFlags) &&
         "PC-Relative control transfer expected");

  // Get branch offset of the branch instruction
  const MachineOperand &MO = MI->getOperand(0);
  assert(MO.isImm() && "Expected immediate operand not found");
  int64_t BranchOffset = MO.getImm();
  MCInstRaiser *MCIR = getMCInstRaiser();
  // Get MCInst offset - the offset of machine instruction in the binary
  uint64_t MCInstOffset = MCIR->getMCInstIndex(*MI);

  assert(MCIR != nullptr && "MCInstRaiser not initialized");
  int64_t BranchTargetOffset =
      MCInstOffset + MCIR->getMCInstSize(MCInstOffset) + BranchOffset;
  const int64_t TgtMBBNo = MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset);
  assert((TgtMBBNo != -1) && "No branch target found");
  auto iter = mbbToBBMap.find(TgtMBBNo);
  assert(iter != mbbToBBMap.end() &&
         "BasicBlock corresponding to MachineInstr branch not found");
  BasicBlock *TgtBB = (*iter).second;
  if (MI->isUnconditionalBranch()) {
    // Just create a branch instruction targeting TgtBB
    BranchInst *UncondBr = BranchInst::Create(TgtBB);
    CandBB->getInstList().push_back(UncondBr);
    CTRec->Raised = true;
  } else if (MI->isConditionalBranch()) {
    // Find the fall through basic block
    MCInstRaiser::const_mcinst_iter MCIter = MCIR->getMCInstAt(MCInstOffset);
    LLVMContext &Ctx(MF.getFunction().getContext());
    // Go to next instruction
    MCIter++;
    assert(MCIter != MCIR->const_mcinstr_end() &&
           "Attempt to go past MCInstr stream");
    // Get MBB number whose lead instruction is at the offset of next
    // instruction. This is the fall-through MBB.
    int64_t FTMBBNum = MCIR->getMBBNumberOfMCInstOffset((*MCIter).first);
    assert((FTMBBNum != -1) && "No fall-through target found");
    // Find raised BasicBlock corresponding to fall-through MBB
    auto mapIter = mbbToBBMap.find(FTMBBNum);
    assert(mapIter != mbbToBBMap.end() &&
           "Fall-through BasicBlock corresponding to MachineInstr branch not "
           "found");
    BasicBlock *FTBB = (*mapIter).second;
    // Get the condition value
    assert(CTRec->RegValues.size() == EFlagBits.size() &&
           "Unexpected number of ELFAGS bit values in conditional branch not "
           "handled");

    // Branch condition value
    Value *BranchCond = nullptr;
    // Predicate operation to be performed
    Value *TrueValue = ConstantInt::getTrue(Ctx);
    Value *FalseValue = ConstantInt::getFalse(Ctx);
    auto Opcode = MI->getOpcode();
    assert(((Opcode == X86::JCC_1) || (Opcode == X86::JCC_2) ||
            (Opcode == X86::JCC_4)) &&
           "Conditional branch instruction expected");
    X86::CondCode CC = X86::COND_INVALID;

    // Unfortunately X86::getCondFromBranch(MI) only looks at JCC_1. We need
    // to handle JCC_2 and JCC_4 as well.
    switch (MI->getOpcode()) {
    default:
      CC = X86::COND_INVALID;
      break;
    case X86::JCC_1:
    case X86::JCC_2:
    case X86::JCC_4:
      CC = static_cast<X86::CondCode>(
          MI->getOperand(MI->getDesc().getNumOperands() - 1).getImm());
    }

    switch (CC) {
    case X86::COND_B: {
      // Test CF == 1
      int CFIndex = getEflagBitIndex(EFLAGS::CF);
      Value *CFValue = CTRec->RegValues[CFIndex];
      assert(CFValue != nullptr &&
             "Failed to get EFLAGS value while raising JB");
      // Construct a compare instruction
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, CFValue, TrueValue,
                                "CmpCF_JB");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_E: {
      // Test ZF == 1
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising JE");
      // Construct a compare instruction
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue, TrueValue,
                                "CmpZF_JE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_NE: {
      // Test ZF == 0
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising JNE");
      // Construct a compare instruction
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue,
                                FalseValue, "CmpZF_JNE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_S: {
      // Test SF == 1
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      assert(SFValue != nullptr &&
             "Failed to get EFLAGS value while raising JS");
      // Construct a compare instruction
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, SFValue, TrueValue,
                                "CmpSF_JS");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_NS: {
      // Test SF == 0
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      assert(SFValue != nullptr &&
             "Failed to get EFLAGS value while raising JNS");
      // Construct a compare instruction
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, SFValue,
                                FalseValue, "CmpSF_JNS");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_A: {
      // CF == 0 and ZF == 0
      int CFIndex = getEflagBitIndex(EFLAGS::CF);
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *CFValue = CTRec->RegValues[CFIndex];
      Value *ZFValue = CTRec->RegValues[ZFIndex];

      assert((CFValue != nullptr) && (ZFValue != nullptr) &&
             "Failed to get EFLAGS value while raising JA");
      // Test CF == 0
      Instruction *CFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, CFValue,
                                         FalseValue, "CFCmp_JA");
      CandBB->getInstList().push_back(CFCond);
      // Test ZF == 0
      Instruction *ZFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue,
                                         FalseValue, "ZFCmp_JA");
      CandBB->getInstList().push_back(ZFCond);
      BranchCond = BinaryOperator::CreateAnd(ZFCond, CFCond, "CFAndZF_JA");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_AE: {
      // CF == 0
      int CFIndex = getEflagBitIndex(EFLAGS::CF);
      Value *CFValue = CTRec->RegValues[CFIndex];
      assert(CFValue != nullptr &&
             "Failed to get EFLAGS value while raising JAE");
      // Compare CF == 0
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, CFValue,
                                FalseValue, "CFCmp_JAE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_BE: {
      // CF == 1 or ZF == 1
      int CFIndex = getEflagBitIndex(EFLAGS::CF);
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *CFValue = CTRec->RegValues[CFIndex];
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      assert((CFValue != nullptr) && (ZFValue != nullptr) &&
             "Failed to get EFLAGS value while raising JBE");
      // Compare CF == 1
      Instruction *CFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, CFValue,
                                         TrueValue, "CFCmp_JBE");
      CandBB->getInstList().push_back(CFCond);
      // Compare ZF == 1
      Instruction *ZFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue,
                                         TrueValue, "ZFCmp_JBE");
      CandBB->getInstList().push_back(ZFCond);
      BranchCond = BinaryOperator::CreateOr(ZFCond, CFCond, "CFAndZF_JBE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_G: {
      // ZF == 0 and (SF == OF)
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      Instruction *ZFCond = nullptr;
      Instruction *SFOFCond = nullptr;
      assert(((ZFValue != nullptr) && (SFValue != nullptr) &&
              (OFValue != nullptr)) &&
             "Failed to get EFLAGS value while raising JG");
      // Compare ZF and 0
      ZFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue, FalseValue,
                            "ZFCmp_JG");
      CandBB->getInstList().push_back(ZFCond);
      // Test SF == OF
      SFOFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, SFValue, OFValue,
                              "SFOFCmp_JG");
      CandBB->getInstList().push_back(SFOFCond);
      BranchCond = BinaryOperator::CreateAnd(ZFCond, SFOFCond, "ZFAndSFOF_JG");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_GE: {
      // SF == OF
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      assert(SFValue != nullptr && OFValue != nullptr &&
             "Failed to get EFLAGS value while raising JGE");
      // Compare SF and OF
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, SFValue, OFValue,
                                "CmpSFOF_JGE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_L: {
      // SF != OF
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      assert(((SFValue != nullptr) && (OFValue != nullptr)) &&
             "Failed to get EFLAGS value while raising JL");
      // Test SF != OF
      BranchCond = new ICmpInst(CmpInst::Predicate::ICMP_NE, SFValue, OFValue,
                                "SFAndOF_JL");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_LE: {
      // ZF == 1 or (SF != OF)
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      Instruction *ZFCond = nullptr;
      Instruction *SFOFCond = nullptr;
      assert(((ZFValue != nullptr) && (SFValue != nullptr) &&
              (OFValue != nullptr)) &&
             "Failed to get EFLAGS value while raising JLE");
      // Compare ZF and 1
      ZFCond = new ICmpInst(CmpInst::Predicate::ICMP_EQ, ZFValue, TrueValue,
                            "CmpZF_JLE");
      CandBB->getInstList().push_back(ZFCond);
      // Test SF != OF
      SFOFCond = new ICmpInst(CmpInst::Predicate::ICMP_NE, SFValue, OFValue,
                              "CmpOF_JLE");
      CandBB->getInstList().push_back(SFOFCond);
      BranchCond = BinaryOperator::CreateOr(ZFCond, SFOFCond, "ZFOrSF_JLE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_INVALID:
      assert(false && "Invalid condition on branch");
      break;
    default:
      MI->dump();
      assert(false && "Unhandled conditional branch");
    }

    // Create branch instruction
    BranchInst *CondBr = BranchInst::Create(TgtBB, FTBB, BranchCond);
    CandBB->getInstList().push_back(CondBr);
    CTRec->Raised = true;
  } else {
    assert(false && "Unhandled type of branch instruction");
  }
  return true;
}

// Raise a generic instruction. This is the catch all MachineInstr raiser
bool X86MachineInstructionRaiser::raiseGenericMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  bool success = false;

  // Now raise the instruction according to the opcode kind
  switch (getInstructionKind(Opcode)) {
  case InstructionKind::BINARY_OP_WITH_IMM:
    success = raiseBinaryOpImmToRegMachineInstr(MI);
    break;
  case InstructionKind::BINARY_OP_MRI_OR_MRC:
    success = raiseBinaryOpMRIOrMRCEncodedMachineInstr(MI);
    break;
  case InstructionKind::CONVERT_BWWDDQ:
    success = raiseConvertBWWDDQMachineInstr(MI);
    break;
  case InstructionKind::CONVERT_WDDQQO:
    success = raiseConvertWDDQQOMachineInstr(MI);
    break;
  case InstructionKind::LEA_OP:
    success = raiseLEAMachineInstr(MI);
    break;
  case InstructionKind::MOV_RR:
    success = raiseMoveRegToRegMachineInstr(MI);
    break;
  case InstructionKind::MOV_RI:
    success = raiseMoveImmToRegMachineInstr(MI);
    break;
  case InstructionKind::BINARY_OP_RR:
    success = raiseBinaryOpRegToRegMachineInstr(MI);
    break;
  case InstructionKind::SETCC:
    success = raiseSetCCMachineInstr(MI);
    break;
  case InstructionKind::COMPARE:
    success = raiseCompareMachineInstr(MI, false, nullptr);
    break;
  case InstructionKind::FPU_REG_OP:
    success = raiseFPURegisterOpInstr(MI);
    break;
  case InstructionKind::DIVIDE_REG_OP: {
    const MachineOperand &SrcOp = MI.getOperand(0);
    assert(SrcOp.isReg() &&
           "Expect register source operand of a div instruction");
    Value *SrcVal =
        getRegOrArgValue(SrcOp.getReg(), MI.getParent()->getNumber());
    success = raiseDivideInstr(MI, SrcVal);
  } break;
  default: {
    outs() << "*** Generic instruction not raised : ";
    MI.dump();
    success = false;
  }
  }
  return success;
}

// Raise a return instruction.
bool X86MachineInstructionRaiser::raiseReturnMachineInstr(
    const MachineInstr &MI) {
  Type *RetType = raisedFunction->getReturnType();
  Value *RetValue = nullptr;

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  if (!RetType->isVoidTy()) {
    unsigned int retReg =
        (RetType->getPrimitiveSizeInBits() == 64) ? X86::RAX : X86::EAX;
    RetValue =
        raisedValues->getReachingDef(retReg, MI.getParent()->getNumber());
  }
  // Create return instruction
  Instruction *retInstr =
      ReturnInst::Create(MF.getFunction().getContext(), RetValue);
  RaisedBB->getInstList().push_back(retInstr);

  return true;
}

bool X86MachineInstructionRaiser::raiseBranchMachineInstrs() {
  if (PrintPass) {
    outs() << "CFG : Before Raising Terminator Instructions\n";
    raisedFunction->dump();
  }

  // Raise branch instructions with control transfer records
  bool success = true;
  for (ControlTransferInfo *CTRec : CTInfo) {
    if (CTRec->CandidateMachineInstr->isBranch()) {
      const MachineInstr *MI = CTRec->CandidateMachineInstr;
      const MCInstrDesc &MCID = MI->getDesc();
      uint64_t imm = MCID.TSFlags & X86II::ImmMask;

      if ((imm == X86II::Imm8PCRel) || (imm == X86II::Imm16PCRel) ||
          (imm == X86II::Imm32PCRel)) {
        success &= raiseDirectBranchMachineInstr(CTRec);
        assert(success && "Failed to raise direct branch instruction");
      } else {
        success &= raiseIndirectBranchMachineInstr(CTRec);
        assert(success && "Failed to raise indirect branch instruction");
      }
    }
  }

  // Delete all ControlTransferInfo records of branch instructions
  // that were raised.
  if (!CTInfo.empty()) {
    CTInfo.erase(
        std::remove_if(CTInfo.begin(), CTInfo.end(),
                       [](const ControlTransferInfo *r) { return r->Raised; }),
        CTInfo.end());
  }
  assert(CTInfo.empty() && "Unhandled branch instructions exist");

  // Note that for basic blocks that fall-through and have no terminator,
  // no control transfer record is created. Insert branch instructions
  // at the end of all such blocks.

  // Walk basic blocks of the MachineFunction.
  for (MachineFunction::iterator mfIter = MF.begin(), mfEnd = MF.end();
       mfIter != mfEnd; mfIter++) {
    MachineBasicBlock &MBB = *mfIter;
    // Get the number of MachineBasicBlock being looked at.
    // If MBB has no terminators, insert a branch to the fall through edge.
    if (MBB.getFirstTerminator() == MBB.end()) {
      if (MBB.succ_size() > 0) {
        // Find the BasicBlock corresponding to MBB
        auto iter = mbbToBBMap.find(MBB.getNumber());
        assert(iter != mbbToBBMap.end() &&
               "Unable to find BasicBlock to insert unconditional branch");
        BasicBlock *BB = iter->second;

        // Find the BasicBlock corresponding to the successor of MBB
        MachineBasicBlock *SuccMBB = *(MBB.succ_begin());
        iter = mbbToBBMap.find(SuccMBB->getNumber());
        assert(iter != mbbToBBMap.end() &&
               "Unable to find successor BasicBlock");
        BasicBlock *SuccBB = iter->second;

        // Create a branch instruction targeting SuccBB
        BranchInst *UncondBr = BranchInst::Create(SuccBB);
        BB->getInstList().push_back(UncondBr);
      }
    }
  }
  if (PrintPass) {
    outs() << "CFG : After Raising Terminator Instructions\n";
    raisedFunction->dump();
  }

  return true;
}

// Raise FPU instructions
bool X86MachineInstructionRaiser::raiseFPURegisterOpInstr(
    const MachineInstr &MI) {

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Construct the appropriate instruction
  unsigned Opcode = MI.getOpcode();
  switch (Opcode) {
  case X86::MUL_FPrST0:
  case X86::DIV_FPrST0: {
    Value *St0Val = FPURegisterStackGetValueAt(0);
    assert((St0Val != nullptr) && "Failed to get ST(0) value");
    Type *St0ValTy = St0Val->getType();
    assert(St0ValTy->isFloatingPointTy() &&
           "Unexpected non-FP value on FPU register stack");
    assert((MI.getNumExplicitOperands() == 1) &&
           "Unexpected number of operands in FP register op instruction "
           "format");
    const MachineOperand &StRegOp = MI.getOperand(0);
    assert(StRegOp.isReg() &&
           "Unexpected non-register operand of FP register op instruction");
    int8_t FPRegIndex = StRegOp.getReg() - X86::ST0;
    assert((FPRegIndex >= 0) && (FPRegIndex < FPUSTACK_SZ) &&
           "Unexpected FPU register stack index computed");
    Value *StVal = FPURegisterStackGetValueAt(FPRegIndex);
    assert((StVal != nullptr) && "Failed to get value of FPU register");
    if (StVal->getType() != St0ValTy) {
      CastInst *CInst = CastInst::Create(
          CastInst::getCastOpcode(StVal, false, St0ValTy, false), StVal,
          St0ValTy);
      RaisedBB->getInstList().push_back(CInst);
      StVal = CInst;
    }
    // Create fmul
    Instruction *FPRegOpInstr = nullptr;
    if (Opcode == X86::MUL_FPrST0) {
      FPRegOpInstr = BinaryOperator::CreateFMul(StVal, St0Val);
    } else if (Opcode == X86::DIV_FPrST0) {
      FPRegOpInstr = BinaryOperator::CreateFDiv(StVal, St0Val);
    }
    RaisedBB->getInstList().push_back(FPRegOpInstr);
    // Update the FP register FPRegIndex with FPRegOpInstr
    FPURegisterStackSetValueAt(FPRegIndex, FPRegOpInstr);
    // Pop FPU register stack
    FPURegisterStackPop();
  } break;
  default: {
    assert(false && "Unhandled FPU instruction");
  } break;
  }

  return true;
}

// Raise Call instruction
bool X86MachineInstructionRaiser::raiseCallMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  bool Success = false;
  switch (Opcode) {
    // case X86::CALLpcrel16   :
    // case X86::CALLpcrel32   :
  case X86::CALL64pcrel32:
  case X86::JMP_1:
  case X86::JMP_4: {
    Function *CalledFunc = getCalledFunction(MI);
    LLVMContext &Ctx(MF.getFunction().getContext());

    assert(CalledFunc != nullptr && "Failed to detect call target");
    std::vector<Value *> CallInstFuncArgs;
    unsigned NumArgs = CalledFunc->arg_size();
    Argument *CalledFuncArgs = CalledFunc->arg_begin();

    if (CalledFunc->isVarArg()) {
      // Discover argument registers that are live just before the CallMI.
      // Liveness of the blocks is already computed in
      // getRaisedFunctionPrototype(). So no need to run it again since no
      // MBB would be modified.
      // MachineBasicBlock::const_reverse_iterator CallInstIter(MI);
      // Find the highest argument register that is defined in the block
      // before the CallMI. NOTE : We assume that all arguments are setup
      // prior to the call. This argument setup manifests as defines in the
      // block or a combination of argument registers that are live-in and
      // defines in the block. Additionally, if the block has more than one
      // calls, it is assumed that call setup for all calls other than the
      // first is done entirely in the block after the preceding call. In
      // such a situation, there is no need to look for argument registers
      // in the live-ins of the block.

      // Bit mask to keep track of argument register positions already
      // discovered.
      uint8_t PositionMask = 0;

      const MachineBasicBlock *CurMBB = MI.getParent();
      // If an argument register does not have a definition in a block that
      // has a call instruction between block entry and MI, there is no need
      // (and is not correct) to look for a reaching definition in its
      // predecessors.
      bool HasCallInst = false;
      unsigned int ArgNo = 1;
      // Find if CurMBB has call between block entry and MI

      for (auto ArgReg : GPR64ArgRegs64Bit) {
        if (hasPhysRegDefInBlock(ArgReg, &MI, CurMBB, MCID::Call, HasCallInst))
          PositionMask |= (1 << ArgNo);
        else if (!HasCallInst) {
          // Look to see if the argument register has a reaching definition in
          // the predecessors of CurMBB.
          unsigned int ReachDefPredEdgeCount = 0;

          for (auto P : CurMBB->predecessors()) {
            SmallVector<MachineBasicBlock *, 8> WorkList;
            // No blocks visited in this walk up the predecessor P
            BitVector BlockVisited(MF.getNumBlockIDs(), false);

            // Start at predecessor P
            WorkList.push_back(P);

            while (!WorkList.empty()) {
              MachineBasicBlock *PredMBB = WorkList.pop_back_val();
              if (!BlockVisited[PredMBB->getNumber()]) {
                // Mark block as visited
                BlockVisited.set(PredMBB->getNumber());
                // Need to consider definitions after any call instructions in
                // the block. This is the reason we can not use
                // getReachingDefs() which does not consider the position
                // where the register is defined.
                bool Ignored;
                if (hasPhysRegDefInBlock(ArgReg, nullptr, PredMBB, MCID::Call,
                                         Ignored))
                  ReachDefPredEdgeCount++;
                else {
                  // Reach info not found, continue walking the predecessors
                  // of CurBB.
                  for (auto P : PredMBB->predecessors()) {
                    // push_back the block which was not visited.
                    if (!BlockVisited[P->getNumber()])
                      WorkList.push_back(P);
                  }
                }
              } else if (PredMBB->getNumber() == CurMBB->getNumber())
                // This is a loop. Simply increment ReachDefPredEdgeCount to
                // indicate that we have a reaching def.
                ReachDefPredEdgeCount++;
            }
          }
          // If there is a reaching def on all predecessor edges then consider
          // it as an argument used by the variadic function.
          if ((ReachDefPredEdgeCount > (unsigned)0) &&
              (ReachDefPredEdgeCount == CurMBB->pred_size()))
            PositionMask |= (1 << ArgNo);
        }
        ArgNo++;
      }

      // Find the number of arguments
      // NOTE: Handling register arguments - 6 in number. Need to handle
      // arguments passed on stack make sure bit 8 and bit 0 are not set
      assert(!(PositionMask & 1) && !(PositionMask & (1 << 7)) &&
             "Invalid number of arguments discovered");
      uint8_t ShftPositionMask = PositionMask >> 1;
      uint8_t NumArgsDiscovered = 0;
      // Consider only consecutive argument registers.
      while (ShftPositionMask & 1) {
        ShftPositionMask = ShftPositionMask >> 1;
        NumArgsDiscovered++;
      }
      // If number of arguments discovered is greater than CalledFunc
      // arguments use that as the number of arguments of the called
      // function.
      if (NumArgsDiscovered > NumArgs) {
        NumArgs = NumArgsDiscovered;
      }
    }
    // Construct the argument list with values to be used to construct a new
    // CallInst. These values are those of the physical registers as defined
    // in C calling convention (the calling convention currently supported).
    for (unsigned i = 0; i < NumArgs; i++) {
      // Get the values of argument registers
      // Do not match types since we are explicitly using 64-bit GPR array.
      // Any necessary casting will be done later in this function.
      Value *ArgVal =
          getRegOrArgValue(GPR64ArgRegs64Bit[i], MI.getParent()->getNumber());
      // This condition will not be true for varargs of a variadic function.
      // In that case just add the value.
      if (i < CalledFunc->arg_size()) {
        // If the ConstantInt value is being treated as a pointer (i.e., is
        // an address, try to construct the associated global read-only data
        // value.
        Argument &FuncArg = CalledFuncArgs[i];
        if (isa<ConstantInt>(ArgVal)) {
          ConstantInt *Address = dyn_cast<ConstantInt>(ArgVal);
          if (!Address->isNegative()) {
            Value *RefVal =
                const_cast<Value *>(getOrCreateGlobalRODataValueAtOffset(
                    Address->getSExtValue(), Address->getType()));
            if (RefVal != nullptr) {
              assert(RefVal->getType()->isPointerTy() &&
                     "Non-pointer type of global value abstracted from "
                     "address");
              ArgVal = RefVal;
            }
          }
        }
        ArgVal = castValue(ArgVal, FuncArg.getType(), RaisedBB);
      }
      assert(ArgVal != nullptr && "Unexpected null argument value");
      CallInstFuncArgs.push_back(ArgVal);
    }

    // Construct call inst.
    Instruction *callInst =
        CallInst::Create(CalledFunc, ArrayRef<Value *>(CallInstFuncArgs));

    // If this is a branch being turned to a tail call set the flag
    // accordingly.
    if (MI.isBranch())
      dyn_cast<CallInst>(callInst)->setTailCall(true);

    RaisedBB->getInstList().push_back(callInst);
    // A function call with a non-void return will modify
    // RAX (or its sub-register).
    Type *RetType = CalledFunc->getReturnType();
    if (!RetType->isVoidTy()) {
      unsigned int RetReg = X86::NoRegister;
      if (RetType->isPointerTy()) {
        // Cast pointer return type to 64-bit type
        Type *CastTy = Type::getInt64Ty(Ctx);
        Instruction *castInst = CastInst::Create(
            CastInst::getCastOpcode(callInst, false, CastTy, false), callInst,
            CastTy);
        RaisedBB->getInstList().push_back(castInst);
        callInst = castInst;
        RetReg = X86::RAX;
      } else {
        switch (RetType->getScalarSizeInBits()) {
        case 64:
          RetReg = X86::RAX;
          break;
        case 32:
          RetReg = X86::EAX;
          break;
        case 16:
          RetReg = X86::AX;
          break;
        case 8:
          RetReg = X86::AL;
          break;
        default:
          assert(false && "Unhandled return value size");
        }
      }
      raisedValues->setPhysRegSSAValue(RetReg, MI.getParent()->getNumber(),
                                       callInst);
    }
    if (MI.isBranch()) {
      // Emit appropriate ret instruction. There will be no ret instruction
      // in the binary since this is a tail call.
      Instruction *RetInstr;
      if (RetType->isVoidTy())
        RetInstr = ReturnInst::Create(Ctx);
      else
        RetInstr = ReturnInst::Create(Ctx, callInst);
      RaisedBB->getInstList().push_back(RetInstr);
    }
    // Add 'unreachable' instruction after callInst if it is a call to glibc
    // function 'void exit(int)'
    if (CalledFunc->getName().equals("exit")) {
      FunctionType *FT = CalledFunc->getFunctionType();
      if (FT->getReturnType()->isVoidTy() && (FT->getNumParams() == 1) &&
          FT->getParamType(0)->isIntegerTy(32)) {
        Instruction *UR = new UnreachableInst(Ctx);
        RaisedBB->getInstList().push_back(UR);
      }
    }
    Success = true;
  } break;
  default: {
    assert(false && "Unhandled call instruction");
  } break;
  }

  return Success;
}

// Top-level function that calls appropriate function that raises
// a MachineInstruction.
// Returns true upon success.

bool X86MachineInstructionRaiser::raiseMachineInstr(MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();

  if (MIDesc.mayLoad() || MIDesc.mayStore()) {
    return raiseMemRefMachineInstr(MI);
  } else if (MIDesc.isReturn()) {
    return raiseReturnMachineInstr(MI);
  } else {
    return raiseGenericMachineInstr(MI);
  }
  return false;
}

// Raise MachineInstr in MachineFunction to MachineInstruction

bool X86MachineInstructionRaiser::raiseMachineFunction() {
  Function *CurFunction = getRaisedFunction();
  LLVMContext &Ctx(CurFunction->getContext());

  // Initialize the raised value tracking mechanism.
  raisedValues = new X86RaisedValueTracker(this);

  Value *Zero64BitValue =
      ConstantInt::get(Type::getInt64Ty(Ctx), 0, false /* isSigned */);

  // Start with an assumption that value of EFLAGS is 0 at the
  // entry of each function.
  for (auto b : EFlagBits)
    // raisedValues->setPhysRegSSAValue(b, 0, Zero1BitValue);
    raisedValues->setEflagValue(b, 0, false);

  // Set values of some registers that appear to be used in main function to
  // 0.
  if (CurFunction->getName().equals("main")) {
    raisedValues->setPhysRegSSAValue(X86::RCX, 0, Zero64BitValue);
  }

  // Walk basic blocks of the MachineFunction in LoopTraversal - except that
  // do not walk the block coming from back edge.By performing this
  // traversal, the idea is to make sure predecessors are translated before
  // a block.

  // Raise all non control transfer MachineInstrs of each MachineBasicBlocks
  // of MachineFunction, except branch instructions.
  LoopTraversal Traversal;
  LoopTraversal::TraversalOrder TraversedMBBOrder = Traversal.traverse(MF);
  for (LoopTraversal::TraversedMBBInfo TraversedMBB : TraversedMBBOrder) {
    // Only perform the primary pass as we do not want to translate one
    // block more than once.
    if (!TraversedMBB.PrimaryPass)
      continue;
    MachineBasicBlock &MBB = *(TraversedMBB.MBB);
    // Get the number of MachineBasicBlock being looked at.
    int MBBNo = MBB.getNumber();
    // Name of the corresponding BasicBlock to be created
    std::string BBName = MBBNo == 0 ? "entry" : "bb." + std::to_string(MBBNo);
    // Create a BasicBlock instance corresponding to MBB being looked at.
    // The raised form of MachineInstr of MBB will be added to curBlock.
    BasicBlock *CurIBB = BasicBlock::Create(Ctx, BBName, CurFunction);
    // Record the mapping of the number of MBB to corresponding BasicBlock.
    // This information is used to raise branch instructions, if any, of the
    // MBB in a later walk of MachineBasicBlocks of MF.
    mbbToBBMap.insert(std::make_pair(MBBNo, CurIBB));
    // Walk MachineInsts of the MachineBasicBlock
    for (MachineInstr &MI : MBB.instrs()) {
      // Ignore noop instructions.
      if (isNoop(MI.getOpcode())) {
        continue;
      }
      // If this is a terminator instruction, record
      // necessary information to raise it in a later pass.
      if (MI.isTerminator() && !MI.isReturn()) {
        recordMachineInstrInfo(MI);
        continue;
      }
      if (MI.isCall()) {
        if (!raiseCallMachineInstr(MI)) {
          return false;
        }
      } else if (!raiseMachineInstr(MI)) {
        return false;
      }
    }
  }
  if (adjustStackAllocatedObjects()) {
    return raiseBranchMachineInstrs() && handleUnpromotedReachingDefs();
  }

  return false;
}

bool X86MachineInstructionRaiser::raise() { return raiseMachineFunction(); }

// NOTE : The following X86ModuleRaiser class function is defined here as
// they reference MachineFunctionRaiser class that has a forward declaration
// in ModuleRaiser.h.

// Create a new MachineFunctionRaiser object and add it to the list of
// MachineFunction raiser objects of this module.
MachineFunctionRaiser *X86ModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *F, const ModuleRaiser *MR, uint64_t Start, uint64_t End) {
  MachineFunctionRaiser *MFR = new MachineFunctionRaiser(
      *M, MR->getMachineModuleInfo()->getOrCreateMachineFunction(*F), MR, Start,
      End);
  MFR->setMachineInstrRaiser(new X86MachineInstructionRaiser(
      MFR->getMachineFunction(), MR, MFR->getMCInstRaiser()));
  mfRaiserVector.push_back(MFR);
  return MFR;
}
