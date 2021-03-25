//===- IREmitter.cpp - Binary raiser utility llvm-mctoll ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of IREmitter class or use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "IREmitter.h"
#include "ARMModuleRaiser.h"
#include "SelectionCommon.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"

using namespace llvm;

IREmitter::IREmitter(BasicBlock *bb, DAGRaisingInfo *dagInfo,
                     FunctionRaisingInfo *funcInfo)
    : FT(bb->getParent()), BB(bb), CurBB(bb), DAGInfo(dagInfo),
      DAG(&dagInfo->getCurDAG()), CTX(DAG->getContext()), FuncInfo(funcInfo),
      DLT(funcInfo->DLT), MR(funcInfo->MR), IRB(bb) {}

// Map ISD opcode to Instruction opcode. But some instruction opcode without
// corresponding ISD opcode mapping.
static int raiseISDOpcodeToInstruction(unsigned Opcode) {
  enum InstructionOpcodes {
#define HANDLE_INST(NUM, OPCODE, CLASS) OPCODE = NUM,
#define LAST_OTHER_INST(NUM) InstructionOpcodesCount = NUM
#include "llvm/IR/Instruction.def"
#define INVALID_INST (InstructionOpcodesCount + 1)
  };
  switch (Opcode) {
  default:
    return INVALID_INST;
  case ISD::ADD:
  case ARMISD::CMOV:
    return Add;
  case ISD::FADD:
    return FAdd;
  case ISD::SUB:
    return Sub;
  case ISD::FSUB:
    return FSub;
  case ISD::MUL:
    return Mul;
  case ISD::FMUL:
    return FMul;
  case ISD::UDIV:
    return UDiv;
  case ISD::SDIV:
    return SDiv;
  case ISD::FDIV:
    return FDiv;
  case ISD::UREM:
    return URem;
  case ISD::SREM:
    return SRem;
  case ISD::FREM:
    return FRem;
  case ISD::SHL:
    return Shl;
  case ISD::SRL:
    return LShr;
  case ISD::SRA:
    return AShr;
  case ISD::AND:
    return And;
  case ISD::OR:
    return Or;
  case ISD::XOR:
    return Xor;
  case EXT_ARMISD::LOAD:
    return Load;
  case EXT_ARMISD::STORE:
    return Store;
  case ISD::TRUNCATE:
    return Trunc;
  case ISD::ZERO_EXTEND:
    return ZExt;
  case ISD::SIGN_EXTEND:
    return SExt;
  case ISD::FP_TO_UINT:
    return FPToUI;
  case ISD::FP_TO_SINT:
    return FPToSI;
  case ISD::UINT_TO_FP:
    return UIToFP;
  case ISD::SINT_TO_FP:
    return SIToFP;
  case ISD::FP_ROUND:
    return FPTrunc;
  case ISD::FP_EXTEND:
    return FPExt;
  case ISD::BITCAST:
    return BitCast;
  case ISD::ADDRSPACECAST:
    return AddrSpaceCast;
  case ISD::SETCC:
    return ICmp;
  case ISD::SELECT:
    return Select;
  case ISD::EXTRACT_VECTOR_ELT:
    return ExtractElement;
  case ISD::INSERT_VECTOR_ELT:
    return InsertElement;
  case ISD::VECTOR_SHUFFLE:
    return ShuffleVector;
  case ISD::MERGE_VALUES:
    return ExtractValue;
  }
}

Value *IREmitter::getIRValue(SDValue val) {
  SDNode *N = val.getNode();

  if (ConstantSDNode::classof(N))
    return const_cast<ConstantInt *>(
        (static_cast<ConstantSDNode *>(N))->getConstantIntValue());

  return DAGInfo->getRealValue(N);
}

static const std::vector<StringRef> CPSR({"N_Flag", "Z_Flag", "C_Flag",
                                          "V_Flag"});

// Match condition state, make corresponding processing.
void IREmitter::emitCondCode(unsigned CondValue, BasicBlock *BB,
                             BasicBlock *IfBB, BasicBlock *ElseBB) {
  switch (CondValue) {
  default:
    break;
  case ARMCC::EQ: { // EQ  Z set
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *InstEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::NE: { // NE Z clear
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *InstEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HS: { // CS  C set
    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *InstEQ = IRB.CreateICmpEQ(C_Flag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LO: { // CC  C clear
    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *InstEQ = IRB.CreateICmpEQ(C_Flag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::MI: { // MI  N set
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *InstEQ = IRB.CreateICmpEQ(N_Flag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::PL: { // PL  N clear
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *InstEQ = IRB.CreateICmpEQ(N_Flag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VS: { // VS  V set
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(V_Flag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VC: { // VC  V clear
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(V_Flag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HI: { // HI  C set & Z clear
    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *InstCEQ = IRB.CreateICmpEQ(C_Flag, IRB.getTrue());
    Value *InstZEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getFalse());
    Value *CondPass = IRB.CreateICmpEQ(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LS: { // LS  C clear or Z set
    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *InstCEQ = IRB.CreateICmpEQ(C_Flag, IRB.getFalse());
    Value *InstZEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getTrue());
    Value *CondPass = IRB.CreateXor(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::GE: { // GE  N = V
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(N_Flag, V_Flag);
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LT: { // LT  N != V
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstNE = IRB.CreateICmpNE(N_Flag, V_Flag);
    IRB.CreateCondBr(InstNE, IfBB, ElseBB);
  } break;
  case ARMCC::GT: { // GT  Z clear & N = V
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstZEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getFalse());
    Value *InstNZEQ = IRB.CreateICmpEQ(N_Flag, V_Flag);
    Value *CondPass = IRB.CreateICmpEQ(InstZEQ, InstNZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LE: { // LE  Z set or N != V
    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);
    Value *InstZEQ = IRB.CreateICmpEQ(Z_Flag, IRB.getTrue());
    Value *InstNZNE = IRB.CreateICmpNE(N_Flag, V_Flag);
    Value *CondPass = IRB.CreateXor(InstZEQ, InstNZNE);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::AL: { // AL
    assert(false && "Emit conditional code [ARMCC::AL]. Should not get here!");
  } break;
  }
}

/// Create PHINode for value use selection when running.
PHINode *IREmitter::createAndEmitPHINode(SDNode *Node, BasicBlock *BB,
                                         BasicBlock *IfBB, BasicBlock *ElseBB,
                                         Instruction *IfInst) {
  PHINode *phi = PHINode::Create(getDefaultType(), 2, "", ElseBB);

  if (FuncInfo->ArgValMap.count(FuncInfo->NodeRegMap[Node]) > 0) {
    phi->addIncoming(FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]], BB);
  } else {
    ConstantInt *zero = ConstantInt::get(getDefaultType(), 0, true);
    Instruction *ti = BB->getTerminator();
    Value *p = BinaryOperator::CreateAdd(zero, zero, "", ti);
    phi->addIncoming(p, BB);
  }

  phi->addIncoming(IfInst, IfBB);
  return phi;
}

/// Update the N Z C V flags of global variable.
/// Implement AddWithCarry of encoding of instruction.
/// AddWithCarry(Operand0, Operand1, Flag);
void IREmitter::emitCPSR(Value *Operand0, Value *Operand1, BasicBlock *BB,
                         unsigned Flag) {
  Module &M = *MR->getModule();
  Type *Ty = IRB.getInt1Ty();
  Type *OperandTy = getDefaultType();
  Function *F_Signed =
      Intrinsic::getDeclaration(&M, Intrinsic::sadd_with_overflow, OperandTy);
  Function *F_Unsigned =
      Intrinsic::getDeclaration(&M, Intrinsic::uadd_with_overflow, OperandTy);
  Value *Args[] = {Operand0, Operand1};
  Value *Unsigned_Sum;
  Value *Signed_Sum;
  if (Flag) {
    Value *OperandFlag = IRB.CreateAdd(Operand0, IRB.getInt32(1));
    Value *Args_Flag[] = {Operand1, OperandFlag};
    Unsigned_Sum = IRB.CreateCall(F_Unsigned, Args_Flag);
    Signed_Sum = IRB.CreateCall(F_Signed, Args_Flag);
  } else {
    Unsigned_Sum = IRB.CreateCall(F_Unsigned, Args);
    Signed_Sum = IRB.CreateCall(F_Signed, Args);
  }

  Value *Sum = ExtractValueInst::Create(Unsigned_Sum, 0, "", BB);
  Value *Result = Sum;
  // Update the corresponding flags.
  // Update N flag.
  Value *N_Flag = IRB.CreateLShr(Result, IRB.getInt32(31));
  Value *NTrunc = IRB.CreateTrunc(N_Flag, Ty);
  IRB.CreateStore(NTrunc, FuncInfo->AllocaMap[0]);

  // Update Z flag.
  Value *Z_Flag = IRB.CreateICmpEQ(Result, IRB.getInt32(0));
  Value *ZTrunc = IRB.CreateTrunc(Z_Flag, Ty);
  IRB.CreateStore(ZTrunc, FuncInfo->AllocaMap[1]);

  // Update C flag.
  Value *C_Flag = ExtractValueInst::Create(Unsigned_Sum, 1, "", BB);
  IRB.CreateStore(C_Flag, FuncInfo->AllocaMap[2]);

  // Update V flag.
  Value *V_Flag = ExtractValueInst::Create(Signed_Sum, 1, "", BB);
  IRB.CreateStore(V_Flag, FuncInfo->AllocaMap[3]);
}

void IREmitter::emitSpecialCPSR(Value *Result, BasicBlock *BB, unsigned Flag) {
  Type *Ty = IRB.getInt1Ty();
  // Update N flag.
  Value *N_Flag = IRB.CreateLShr(Result, IRB.getInt32(31));
  N_Flag = IRB.CreateTrunc(N_Flag, Ty);
  IRB.CreateStore(N_Flag, FuncInfo->AllocaMap[0]);
  // Update Z flag.
  Value *Z_Flag = IRB.CreateICmpEQ(Result, IRB.getInt32(0));

  IRB.CreateStore(Z_Flag, FuncInfo->AllocaMap[1]);
}

Type *IREmitter::getIntTypeByPtr(Type *pty) {
  assert(pty && pty->isPointerTy() && "The input type is not a pointer!");
  Type *ty = nullptr;

  if (pty == Type::getInt64PtrTy(*CTX))
    ty = Type::getInt64Ty(*CTX);
  else if (pty == Type::getInt32PtrTy(*CTX))
    ty = Type::getInt32Ty(*CTX);
  else if (pty == Type::getInt16PtrTy(*CTX))
    ty = Type::getInt16Ty(*CTX);
  else if (pty == Type::getInt8PtrTy(*CTX))
    ty = Type::getInt8Ty(*CTX);
  else if (pty == Type::getInt1PtrTy(*CTX))
    ty = Type::getInt1Ty(*CTX);
  else
    ty = getDefaultType();

  return ty;
}

#define HANDLE_EMIT_CONDCODE_COMMON(OPC)                                       \
  BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());            \
  BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());          \
                                                                               \
  emitCondCode(CondValue, BB, IfBB, ElseBB);                                   \
                                                                               \
  Value *Inst = BinaryOperator::Create##OPC(S0, S1);                           \
  IfBB->getInstList().push_back(dyn_cast<Instruction>(Inst));                  \
  PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,                  \
                                      dyn_cast<Instruction>(Inst));            \
  DAGInfo->setRealValue(Node, Phi);                                            \
  FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

#define HANDLE_EMIT_CONDCODE(OPC)                                              \
  HANDLE_EMIT_CONDCODE_COMMON(OPC)                                             \
                                                                               \
  IRB.SetInsertPoint(IfBB);                                                    \
  IRB.CreateBr(ElseBB);                                                        \
  IRB.SetInsertPoint(ElseBB);

void IREmitter::emitBinaryCPSR(Value *Inst, BasicBlock *BB, unsigned Opcode,
                               SDNode *Node) {
  Value *S0 = getIRValue(Node->getOperand(0));
  Value *S1 = getIRValue(Node->getOperand(1));

  switch (Opcode) {
  case Instruction::Add: {
    emitCPSR(S0, S1, BB, 0);
  } break;
  case Instruction::Sub: {
    Value *InstNot = nullptr;
    if (ConstantSDNode::classof(Node->getOperand(1).getNode())) {
      Value *InstTp = IRB.CreateSub(S0, S0);
      Value *InstAdd = IRB.CreateAdd(InstTp, S1);
      InstNot = IRB.CreateNot(InstAdd);
    } else {
      InstNot = IRB.CreateNot(S1, "");
    }
    emitCPSR(S0, InstNot, BB, 1);
  } break;
  case Instruction::And: {
    emitSpecialCPSR(Inst, BB, 0);
  } break;
  case Instruction::Mul: {
    emitSpecialCPSR(Inst, BB, 0);
  } break;
  case Instruction::Or: {
    emitSpecialCPSR(Inst, BB, 0);
    /* How to deal with C Flag? */
  } break;
  case Instruction::Xor: {
    emitSpecialCPSR(Inst, BB, 0);
    /* How to deal with C Flag? */
  } break;
  case Instruction::Shl: {
    emitSpecialCPSR(Inst, BB, 0);

    // Update C flag.
    // extended_x = x : Zeros(shift), c flag = extend_x[N];
    // c flag = (s0 lsl (s1 -1))[31]
    Type *Ty = IRB.getInt1Ty();
    Value *Val = cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
    Value *C_Flag = IRB.CreateSub(S1, Val);
    C_Flag = IRB.CreateShl(S0, C_Flag);
    C_Flag = IRB.CreateLShr(C_Flag, IRB.getInt32(31));
    Value *CTrunc = IRB.CreateTrunc(C_Flag, Ty);

    IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
  } break;
  case Instruction::LShr: {
    emitSpecialCPSR(Inst, BB, 0);

    // Update C flag.
    // c flag = (s0 lsr (s1 -1))[0]
    Type *Ty = IRB.getInt1Ty();
    Value *Val = cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
    Value *C_Flag = IRB.CreateSub(S1, Val);
    C_Flag = IRB.CreateLShr(S0, C_Flag);
    C_Flag = IRB.CreateAnd(C_Flag, Val);
    Value *CTrunc = IRB.CreateTrunc(C_Flag, Ty);

    IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
  } break;
  case Instruction::AShr: {
    emitSpecialCPSR(Inst, BB, 0);

    // Update C flag.
    // c flag = (s0 asr (s1 -1))[0]
    Type *Ty = IRB.getInt1Ty();
    Value *Val = ConstantInt::get(getDefaultType(), 1, true);
    Value *C_Flag = IRB.CreateSub(S1, Val);
    C_Flag = IRB.CreateAShr(S0, C_Flag);
    C_Flag = IRB.CreateAnd(C_Flag, Val);
    Value *CTrunc = IRB.CreateTrunc(C_Flag, Ty);
    IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
  } break;
  }
}

void IREmitter::emitBinary(SDNode *Node) {
  unsigned Opc = Node->getOpcode();
  BasicBlock *BB = getBlock();
  Value *S0 = getIRValue(Node->getOperand(0));
  Value *S1 = getIRValue(Node->getOperand(1));

  int InstOpc = raiseISDOpcodeToInstruction(Opc);

  switch (InstOpc) {
#define HANDLE_BINARY(OPCODE)                                                  \
  case Instruction::OPCODE: {                                                  \
    if (DAGInfo->NPMap[Node]->HasCPSR) {                                       \
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;                         \
      if (!(DAGInfo->NPMap[Node]->UpdateCPSR)) {                               \
        HANDLE_EMIT_CONDCODE(OPCODE)                                           \
      } else if (DAGInfo->NPMap[Node]->Special) {                              \
        HANDLE_EMIT_CONDCODE_COMMON(OPCODE)                                    \
        emitBinaryCPSR(Inst, IfBB, InstOpc, Node);                             \
        IRB.CreateBr(ElseBB);                                                  \
        IRB.SetInsertPoint(ElseBB);                                            \
      } else {                                                                 \
        Value *Inst = IRB.Create##OPCODE(S0, S1);                              \
        DAGInfo->setRealValue(Node, Inst);                                     \
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;                \
        emitBinaryCPSR(Inst, BB, InstOpc, Node);                               \
      }                                                                        \
    } else {                                                                   \
      Value *Inst = BinaryOperator::Create##OPCODE(S0, S1);                    \
      BasicBlock *CBB = IRB.GetInsertBlock();                                  \
      CBB->getInstList().push_back(dyn_cast<Instruction>(Inst));               \
      DAGInfo->setRealValue(Node, Inst);                                       \
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;                  \
    }                                                                          \
    break;                                                                     \
  }
    HANDLE_BINARY(Add)
    HANDLE_BINARY(Sub)
    HANDLE_BINARY(Mul)
    HANDLE_BINARY(Shl)
    HANDLE_BINARY(LShr)
    HANDLE_BINARY(AShr)
    HANDLE_BINARY(And)
    HANDLE_BINARY(Or)
    HANDLE_BINARY(Xor)
  }
}

// Extract the offset of MachineInstr MI from the Metadata operand.
static uint64_t getMCInstIndex(const MachineInstr &MI) {
  unsigned NumExpOps = MI.getNumExplicitOperands();
  const MachineOperand &MO = MI.getOperand(NumExpOps);
  assert(MO.isMetadata() &&
         "Unexpected non-metadata operand in branch instruction!");
  const MDNode *MDN = MO.getMetadata();
  // Unwrap metadata of the instruction to get the MCInstIndex of
  // the MCInst corresponding to this MachineInstr.
  ConstantAsMetadata *CAM = dyn_cast<ConstantAsMetadata>(MDN->getOperand(0));
  assert(CAM != nullptr && "Unexpected metadata type!");
  Constant *CV = CAM->getValue();
  ConstantInt *CI = dyn_cast<ConstantInt>(CV);
  assert(CI != nullptr && "Unexpected metadata constant type!");
  APInt ArbPrecInt = CI->getValue();
  return ArbPrecInt.getSExtValue();
}

/// Generate SDNode code for a target-independent node.
/// Emit SDNode to Instruction and add to BasicBlock.
/// 1. Map ISD opcode to Instruction opcode.
/// 2. Abstract node to instruction.
void IREmitter::emitSDNode(SDNode *Node) {
  unsigned Opc = Node->getOpcode();
  BasicBlock *BB = getBlock();

  IRB.SetCurrentDebugLocation(Node->getDebugLoc());

  // Mapping ISD opcode to Instruction opcode.
  int InstOpc = raiseISDOpcodeToInstruction(Opc);

  enum InstructionOpcodes {
#define HANDLE_INST(NUM, OPCODE, CLASS) OPCODE = NUM,
#define LAST_OTHER_INST(NUM) InstructionOpcodesCount = NUM
#include "llvm/IR/Instruction.def"
  };

  switch (InstOpc) {
  default:
    emitSpecialNode(Node);
    break;
  case Add:
  case Sub:
  case Mul:
  case And:
  case Or:
  case Xor:
  case Shl:
  case AShr:
  case LShr:
    emitBinary(Node);
    break;
  case Load: {
    Value *S = getIRValue(Node->getOperand(0));
    Value *Ptr = nullptr;
    if (S->getType()->isPointerTy())
      Ptr = S;
    else
      Ptr = IRB.CreateIntToPtr(
          S, Node->getValueType(0).getTypeForEVT(*CTX)->getPointerTo());

    Value *Inst = nullptr;
    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      // Create new BB for EQ instructin exectute.
      BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

      // Emit the condition code.
      emitCondCode(CondValue, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);
      if (GlobalVariable::classof(Ptr))
        Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
      else
        Inst = CallCreateAlignedLoad(
            Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

      PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                          dyn_cast<Instruction>(Inst));
      DAGInfo->setRealValue(Node, Phi);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      if (GlobalVariable::classof(Ptr)) {
        // Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
        Inst = new PtrToIntInst(Ptr, getDefaultType(), "", BB);
      } else {
        Inst = CallCreateAlignedLoad(
            Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

        // TODO:
        // Temporary method for this.
        if (Inst->getType() == Type::getInt64Ty(*CTX))
          Inst = IRB.CreateTrunc(Inst, getDefaultType());
        else if (Inst->getType() != getDefaultType())
          Inst = IRB.CreateSExt(Inst, getDefaultType());
      }

      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  case Store: {
    Value *Val = getIRValue(Node->getOperand(0));
    Value *S = getIRValue(Node->getOperand(1));
    Value *Ptr = nullptr;
    Type *Nty = Node->getValueType(0).getTypeForEVT(*CTX);

    if (Val->getType() != Nty) {
      Val = IRB.CreateTrunc(Val, Nty);
    }

    if (S->getType()->isPointerTy()) {
      if (S->getType() != Nty->getPointerTo()) {
        Ptr = IRB.CreateBitCast(S, Nty->getPointerTo());
      } else {
        Ptr = S;
      }
    } else {
      Ptr = IRB.CreateIntToPtr(S, Nty->getPointerTo());
    }

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      // Create new BB for EQ instructin exectute.
      BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

      // Emit the condition code.
      emitCondCode(CondValue, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);

      IRB.CreateAlignedStore(Val, Ptr,
                             MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      IRB.CreateAlignedStore(Val, Ptr,
                             MaybeAlign(Log2(DLT->getPointerPrefAlignment())));
    }
  } break;
  case ICmp: {
    Value *LHS = getIRValue(Node->getOperand(0));
    Value *RHS = getIRValue(Node->getOperand(1));

    Value *InstNot = nullptr;
    if (ConstantSDNode::classof(Node->getOperand(1).getNode())) {
      Value *InstTp = IRB.CreateSub(LHS, LHS);
      Value *InstAdd = IRB.CreateAdd(InstTp, RHS);
      InstNot = IRB.CreateNot(InstAdd);
    } else {
      InstNot = IRB.CreateNot(RHS);
    }
    emitCPSR(LHS, InstNot, BB, 1);
  } break;
  case FCmp: {
    Value *LHS = getIRValue(Node->getOperand(0));
    Value *RHS = getIRValue(Node->getOperand(1));

    Value *InstNot = nullptr;
    if (ConstantSDNode::classof(Node->getOperand(1).getNode())) {
      Value *InstTp = IRB.CreateSub(LHS, LHS);
      Value *InstAdd = IRB.CreateAdd(InstTp, RHS);
      InstNot = IRB.CreateNot(InstAdd);
    } else {
      InstNot = IRB.CreateNot(RHS);
    }

    emitCPSR(LHS, InstNot, BB, 1);
  } break;
  }
}

void IREmitter::emitSpecialNode(SDNode *Node) {
  unsigned Opc = Node->getOpcode();
  Module &M = *MR->getModule();

  BasicBlock *BB = getBlock();
  BasicBlock *CurBB = getCurBlock();
  switch (Opc) {
  default:
    // assert(false && "Unknown SDNode Type!");
    break;
  case EXT_ARMISD::BX_RET: {
    Value *Ret = getIRValue(Node->getOperand(0));
    if (!ConstantSDNode::classof(Node->getOperand(0).getNode()))
      IRB.CreateRet(Ret);
    else
      IRB.CreateRetVoid();
  } break;
  // TODO:
  // Specical instruction we do here. e.g Br Invoke IndirectBr ..
  case ISD::BRCOND: {
    unsigned Cond = cast<ConstantSDNode>(Node->getOperand(1))->getZExtValue();
    // br i1 %cmp, label %if.then, label %if.else
    MachineBasicBlock *MBB = FuncInfo->MBBMap[CurBB];
    MachineBasicBlock::succ_iterator SuI = MBB->succ_begin();
    BasicBlock *Iftrue = FuncInfo->getOrCreateBasicBlock(*SuI);
    MachineBasicBlock *NextMBB = &*std::next(MBB->getIterator());
    BasicBlock *NextBB = FuncInfo->getOrCreateBasicBlock(NextMBB);

    emitCondCode(Cond, BB, Iftrue, NextBB);
  } break;
  case ISD::BR: {
    // br label %xxx
    MachineBasicBlock *LMBB = FuncInfo->MBBMap[CurBB];
    MachineBasicBlock::succ_iterator SuI = LMBB->succ_begin();
    if (SuI != LMBB->succ_end()) {
      BasicBlock *BrDest = FuncInfo->getOrCreateBasicBlock(*SuI);
      IRB.CreateBr(BrDest);
      break;
    }
    LLVM_FALLTHROUGH;
  }
  case EXT_ARMISD::BRD: {
    // Get the function call Index.
    uint64_t Index = Node->getConstantOperandVal(0);
    // Get function from ModuleRaiser.
    Function *CallFunc = MR->getRaisedFunctionAt(Index);
    unsigned IFFuncArgNum = 0; // The argument number which gets from analyzing
                               // variadic function prototype.
    bool IsSyscall = false;
    if (CallFunc == nullptr) {
      // According MI to get BL instruction address.
      // uint64_t callAddr = DAGInfo->NPMap[Node]->InstAddr;
      uint64_t CallAddr = MR->getTextSectionAddress() +
                          getMCInstIndex(*(DAGInfo->NPMap[Node]->MI));
      Function *IndefiniteFunc = MR->getCallFunc(CallAddr);
      CallFunc = MR->getSyscallFunc(Index);
      if (CallFunc != nullptr && IndefiniteFunc != nullptr) {
        IFFuncArgNum = MR->getFunctionArgNum(CallAddr);
        IsSyscall = true;
      }
    }
    assert(CallFunc && "Failed to get called function!");
    // Get argument number from callee.
    unsigned ArgNum = CallFunc->arg_size();
    if (IFFuncArgNum > ArgNum)
      ArgNum = IFFuncArgNum;
    Argument *CalledFuncArgs = CallFunc->arg_begin();
    std::vector<Value *> CallInstFuncArgs;
    CallInst *Inst = nullptr;
    if (ArgNum > 0) {
      Value *ArgVal = nullptr;
      const MachineFrameInfo &MFI = FuncInfo->MF->getFrameInfo();
      unsigned StackArg = 0; // Initialize argument size on stack to 0.
      if (ArgNum > 4) {
        StackArg = ArgNum - 4;

        unsigned StackNum = MFI.getNumObjects() - 2;
        if (StackNum > StackArg)
          StackArg = StackNum;
      }
      for (unsigned i = 0; i < ArgNum; i++) {
        if (i < 4)
          ArgVal = FuncInfo->ArgValMap[ARM::R0 + i];
        else {
          const Value *StackAlloc =
              MFI.getObjectAllocation(StackArg - i - 4 + 1);
          ArgVal = CallCreateAlignedLoad(
              const_cast<Value *>(StackAlloc),
              MaybeAlign(Log2(DLT->getPointerPrefAlignment())));
        }
        if (IsSyscall && i < CallFunc->arg_size() &&
            ArgVal->getType() != CalledFuncArgs[i].getType()) {
          CastInst *CInst = CastInst::Create(
              CastInst::getCastOpcode(ArgVal, false,
                                      CalledFuncArgs[i].getType(), false),
              ArgVal, CalledFuncArgs[i].getType());
          IRB.GetInsertBlock()->getInstList().push_back(CInst);
          ArgVal = CInst;
        }
        CallInstFuncArgs.push_back(ArgVal);
      }
      Inst = IRB.CreateCall(CallFunc, ArrayRef<Value *>(CallInstFuncArgs));
    } else
      Inst = IRB.CreateCall(CallFunc);

    DAGInfo->setRealValue(Node, Inst);
  } break;
  case ISD::BRIND: {
    Value *Func = getIRValue(Node->getOperand(0));
    unsigned NumDests = Node->getNumOperands();
    IRB.CreateIndirectBr(Func, NumDests);
  } break;
  case ISD::BR_JT: {
    // Emit the switch instruction.
    if (jtList.size() > 0) {
      MachineBasicBlock *mbb = FuncInfo->MBBMap[CurBB];
      MachineFunction *MF = mbb->getParent();

      std::vector<JumpTableBlock> JTCases;
      const MachineJumpTableInfo *MJT = MF->getJumpTableInfo();
      unsigned jtIndex = Node->getConstantOperandVal(0);
      std::vector<MachineJumpTableEntry> JumpTables = MJT->getJumpTables();
      for (unsigned j = 0, f = JumpTables[jtIndex].MBBs.size(); j != f; ++j) {
        llvm::Type *i32_type = llvm::IntegerType::getInt32Ty(*CTX);
        llvm::ConstantInt *i32_val =
            cast<ConstantInt>(llvm::ConstantInt::get(i32_type, j, true));
        MachineBasicBlock *Succ = JumpTables[jtIndex].MBBs[j];
        ConstantInt *CaseVal = i32_val;
        JTCases.push_back(std::make_pair(CaseVal, Succ));
      }
      // main->getEntryBlock().setName("entry");

      unsigned int numCases = JTCases.size();
      BasicBlock *def_bb =
          FuncInfo->getOrCreateBasicBlock(jtList[jtIndex].df_MBB);

      BasicBlock *cd_bb =
          FuncInfo->getOrCreateBasicBlock(jtList[jtIndex].conditionMBB);

      // conditon instruction
      Instruction *cdi = nullptr;
      for (BasicBlock::iterator DI = cd_bb->begin(); DI != cd_bb->end(); DI++) {
        Instruction *ins = dyn_cast<Instruction>(DI);
        if (isa<LoadInst>(DI) && !cdi) {
          cdi = ins;
        }

        if (cdi && (ins->getOpcode() == Instruction::Sub)) {
          if (isa<ConstantInt>(ins->getOperand(1))) {
            ConstantInt *opr = dyn_cast<ConstantInt>(ins->getOperand(1));
            if (opr->uge(0)) {
              cdi = ins;
            }
          }
        }
      }

      SwitchInst *Inst = IRB.CreateSwitch(cdi, def_bb, numCases);
      for (unsigned i = 0, e = numCases; i != e; ++i) {
        BasicBlock *case_bb =
            FuncInfo->getOrCreateBasicBlock(JTCases[i].second);
        Inst->addCase(JTCases[i].first, case_bb);
      }
    }
  } break;
  case ISD::ROTR: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));
    Type *Ty = getDefaultType();
    Value *Val = ConstantInt::get(Ty, 32, true);

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;

      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        DAGInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        emitSpecialCPSR(Inst, BB, 0);
      } else {
        // Create new BB for EQ instructin exectute.
        BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(CondValue, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        DAGInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(Val, S1);
      Value *InstLShr = IRB.CreateLShr(S0, S1);
      Value *InstShl = IRB.CreateShl(S0, InstSub);
      Value *Inst = IRB.CreateOr(InstLShr, InstShl);
      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  case ARMISD::RRX: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Type *Ty = getDefaultType();
    Value *Val1 = ConstantInt::get(Ty, 1, true);
    Value *Val2 = ConstantInt::get(Ty, 31, true);
    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;

      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        C_Flag = IRB.CreateZExt(C_Flag, Ty);
        Value *Bit31 = IRB.CreateShl(C_Flag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        DAGInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        /**************************************/
        emitSpecialCPSR(Inst, BB, 0);
        // Update C flag.
        // c flag = s0[0]
        C_Flag = IRB.CreateAnd(S0, Val1);
        IRB.CreateStore(C_Flag, FuncInfo->AllocaMap[2]);
      } else {
        // Create new BB for EQ instructin exectute.
        BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(CondValue, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *C_Flag = nullptr;

        C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        C_Flag = IRB.CreateZExt(C_Flag, Ty);
        Value *Bit31 = IRB.CreateShl(C_Flag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        DAGInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstLShr = IRB.CreateLShr(S0, Val1);
      Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
      C_Flag = IRB.CreateZExt(C_Flag, Ty);
      Value *Bit31 = IRB.CreateShl(C_Flag, Val2);
      Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  case EXT_ARMISD::BIC: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));
    Type *tp = getDefaultType();
    Value *val = ConstantInt::get(tp, -1, true);

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;

      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        Value *InstXor = IRB.CreateXor(val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);

        DAGInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        emitSpecialCPSR(Inst, BB, 0);
        // Update C flag.
        // C flag not change.

        // Update V flag.
        // unchanged.
      } else {
        // Create new BB for EQ instructin exectute.
        BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());
        // Emit the condition code.
        emitCondCode(CondValue, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstXor = IRB.CreateXor(val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);
        PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        DAGInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstXor, *Inst;
      InstXor = IRB.CreateXor(val, S1);
      Inst = IRB.CreateAnd(S0, InstXor);
      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  case ARMISD::CMN: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));
    Value *Inst;
    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      HANDLE_EMIT_CONDCODE_COMMON(Add)
      emitCPSR(S0, S1, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Inst = IRB.CreateAdd(S0, S1);
      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
      emitCPSR(S0, S1, BB, 0);
    }
  } break;
  case ISD::CTLZ: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Function *CTLZ = Intrinsic::getDeclaration(BB->getParent()->getParent(),
                                               Intrinsic::ctlz, S0->getType());
    Type *i1_type = llvm::IntegerType::getInt1Ty(*CTX);
    Value *is_zero_undef = ConstantInt::get(i1_type, true, true);

    std::vector<Value *> Vec;
    Vec.push_back(S0);
    Vec.push_back(is_zero_undef);
    ArrayRef<Value *> Args(Vec);

    Value *Inst = IRB.CreateCall(CTLZ, Args);
    DAGInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  case EXT_ARMISD::MLA: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));
    Value *S2 = getIRValue(Node->getOperand(2));

    Value *InstMul = IRB.CreateMul(S0, S1);
    Value *Inst = IRB.CreateAdd(InstMul, S2);

    DAGInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  case EXT_ARMISD::TST: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      // Create new BB for EQ instructin exectute.
      BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

      // TODO:
      // Not change def. Consider how to use PHI.
      // PHINode *Phi = createAndEmitPHINode(Node, BB, ElseBB);

      emitCondCode(CondValue, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(Inst, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(Inst, BB, 0);
    }
  } break;
  case EXT_ARMISD::SBC: {
    Value *S1 = getIRValue(Node->getOperand(0));
    Value *S2 = getIRValue(Node->getOperand(1));
    Type *Ty = getDefaultType();

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;

      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *C_Flag = nullptr;
        C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        Value *CZext = IRB.CreateZExt(C_Flag, Ty);
        Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
        DAGInfo->setRealValue(Node, InstSBC);
        Value *InstNot = IRB.CreateNot(S2);
        if (1)
          emitCPSR(S1, InstNot, BB, 0);
        else
          emitCPSR(S1, InstNot, BB, 1);
      } else {
        BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
        BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

        emitCondCode(CondValue, BB, IfBB, ElseBB);

        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *C_Flag = nullptr;
        C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        Value *CZext = IRB.CreateZExt(C_Flag, Ty);
        Value *Inst = IRB.CreateAdd(InstSub, CZext);
        PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        DAGInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(S1, S2);
      Value *C_Flag = nullptr;
      C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
      Value *CZext = IRB.CreateZExt(C_Flag, Ty);
      Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
      DAGInfo->setRealValue(Node, InstSBC);
    }
  } break;
  case EXT_ARMISD::TEQ: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      // Create new BB for EQ instructin exectute.
      BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

      // TODO:
      // This instruction not change def, consider phi later.

      emitCondCode(CondValue, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(Inst, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(Inst, BB, 0);
    }
  } break;
  case EXT_ARMISD::MSR: {
    Value *Cond = getIRValue(Node->getOperand(0));
    // 1 1 1 1
    // N set 1 0 0 0   8
    // Z set 0 1 0 0   4
    // C set 0 0 1 0   2
    // Z set 0 0 0 1   1
    IRB.CreateStore(Cond, dyn_cast<Value>(M.getGlobalVariable("Reserved")));
    // Pattern msr CPSR_f, Rn
    if (1) {
      Value *Shift_Num = IRB.getInt32(28);
      Value *Shift = IRB.CreateLShr(Cond, Shift_Num);
      // Update N Flag.
      Value *N_Cmp = IRB.getInt32(8);
      Value *N_Flag = IRB.CreateICmpEQ(Shift, N_Cmp);
      IRB.CreateStore(N_Flag, FuncInfo->AllocaMap[0]);
      // Update Z Flag.
      Value *Z_Cmp = IRB.getInt32(4);
      Value *Z_Flag = IRB.CreateICmpEQ(Shift, Z_Cmp);
      IRB.CreateStore(Z_Flag, FuncInfo->AllocaMap[1]);
      // Update C Flag.
      Value *C_Cmp = IRB.getInt32(2);
      Value *C_Flag = IRB.CreateICmpEQ(Shift, C_Cmp);
      IRB.CreateStore(C_Flag, FuncInfo->AllocaMap[2]);
      // Update V Flag.
      Value *V_Cmp = IRB.getInt32(1);
      Value *V_Flag = IRB.CreateICmpEQ(Shift, V_Cmp);
      IRB.CreateStore(V_Flag, FuncInfo->AllocaMap[3]);
    } else {
      // Pattern msr CSR_f, #const.
    }
  } break;
  case EXT_ARMISD::MRS: {
    Value *Rn = getIRValue(Node->getOperand(0));
    // Reserved || N_Flag << 31 || Z_Flag << 30 || C_Flag << 29 || V_Flag << 28
    PointerType *PtrTy = PointerType::getInt32PtrTy(*CTX);
    Type *Ty = Type::getInt32Ty(*CTX);

    Value *BitNShift = IRB.getInt32(31);
    Value *BitZShift = IRB.getInt32(30);
    Value *BitCShift = IRB.getInt32(29);
    Value *BitVShift = IRB.getInt32(28);

    Value *N_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[0]);
    Value *Z_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[1]);
    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *V_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[3]);

    N_Flag = IRB.CreateZExt(N_Flag, Ty);
    Z_Flag = IRB.CreateZExt(Z_Flag, Ty);
    C_Flag = IRB.CreateZExt(C_Flag, Ty);
    V_Flag = IRB.CreateZExt(V_Flag, Ty);

    Value *N_Shift = IRB.CreateShl(N_Flag, BitNShift);
    Value *Z_Shift = IRB.CreateShl(Z_Flag, BitZShift);
    Value *C_Shift = IRB.CreateShl(C_Flag, BitCShift);
    Value *V_Shift = IRB.CreateShl(V_Flag, BitVShift);
    Value *NZ_Val = IRB.CreateAdd(N_Shift, Z_Shift);
    Value *CV_Val = IRB.CreateAdd(C_Shift, V_Shift);
    Value *NZCV_Val = IRB.CreateAdd(NZ_Val, CV_Val);
    Value *Reserved =
        CallCreateAlignedLoad(dyn_cast<Value>(M.getGlobalVariable("Reserved")));

    Value *CPSR_Val = IRB.CreateAdd(NZCV_Val, Reserved);
    Value *Rn_Ptr = IRB.CreateIntToPtr(Rn, PtrTy);
    Value *RnStore = IRB.CreateStore(CPSR_Val, Rn_Ptr);

    DAGInfo->setRealValue(Node, RnStore);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = RnStore;
  } break;
  case ISD::ADDC: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));
    Type *OperandTy = getDefaultType();

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;

      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        // Create add emit.
        Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        Value *Result = IRB.CreateAdd(S0, S1);
        Value *CZext = IRB.CreateZExt(C_Flag, OperandTy);
        Value *InstADC = IRB.CreateAdd(Result, CZext);
        DAGInfo->setRealValue(Node, InstADC);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] =
            dyn_cast<Instruction>(InstADC);

        // Update CPSR.
        // TODO:
        // Should consider how to do this.
        if (1)
          emitCPSR(S0, S1, BB, 1);
        else
          emitCPSR(S0, S1, BB, 0);
      } else {
        // Create new BB for EQ instructin exectute.
        BasicBlock *IfBB = BasicBlock::Create(*CTX, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(*CTX, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(CondValue, BB, IfBB, ElseBB);

        Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
        IRB.SetInsertPoint(IfBB);
        Value *InstAdd = IRB.CreateAdd(S0, S1);
        Value *CZext = IRB.CreateZExtOrTrunc(C_Flag, OperandTy);
        Value *Inst = IRB.CreateAdd(InstAdd, CZext);
        PHINode *Phi = createAndEmitPHINode(Node, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        DAGInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
      Value *Inst = IRB.CreateAdd(S0, S1);
      Value *CTrunc = IRB.CreateZExtOrTrunc(C_Flag, getDefaultType());
      Value *InstADC = IRB.CreateAdd(Inst, CTrunc);

      DAGInfo->setRealValue(Node, InstADC);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = InstADC;
    }
  } break;
  case EXT_ARMISD::RSC: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));

    Value *C_Flag = CallCreateAlignedLoad(FuncInfo->AllocaMap[2]);
    Value *CZext = IRB.CreateZExt(C_Flag, getDefaultType());

    Value *Inst = IRB.CreateAdd(S0, CZext);
    Inst = IRB.CreateSub(S1, Inst);
    DAGInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  case EXT_ARMISD::UXTB: {
    Value *S1 = getIRValue(Node->getOperand(1));
    Value *Rotation = getIRValue(Node->getOperand(2));
    Value *ror_val = ConstantInt::get(getDefaultType(), 8, true);
    Value *add_val = ConstantInt::get(getDefaultType(), 0, true);
    Value *and_val = ConstantInt::get(getDefaultType(), 0xff, true);
    Value *Inst_mul = IRB.CreateMul(Rotation, ror_val);
    Value *Inst_lshr = IRB.CreateLShr(S1, Inst_mul);
    Value *Inst_add = IRB.CreateAdd(Inst_lshr, add_val);
    Value *Inst_and = IRB.CreateAnd(Inst_add, and_val);
    DAGInfo->setRealValue(Node, Inst_and);
  } break;
  case EXT_ARMISD::RSB: {
    Value *S0 = getIRValue(Node->getOperand(0));
    Value *S1 = getIRValue(Node->getOperand(1));

    if (DAGInfo->NPMap[Node]->HasCPSR) {
      unsigned CondValue = DAGInfo->NPMap[Node]->Cond;
      if (DAGInfo->NPMap[Node]->UpdateCPSR) {
        // Create add emit.
        Value *Inst = IRB.CreateSub(S0, S1);
        DAGInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        Value *InstNot = IRB.CreateNot(S1);
        emitCPSR(InstNot, S0, BB, 1);
      } else {
        HANDLE_EMIT_CONDCODE(Sub)
      }
    } else {
      Value *Inst = IRB.CreateSub(S0, S1);
      DAGInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  }
}
