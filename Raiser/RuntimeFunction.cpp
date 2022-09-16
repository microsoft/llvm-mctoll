//===------------- RuntimeFunction.h --------------*- C++ ---------------*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the definition of functions that generate LLVM IR
// functions as part of raised code. The LLVM IR functions generated per-module
// and are called as needed in the raised code.
//
//===----------------------------------------------------------------------===//

#include "RuntimeFunction.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;
using namespace llvm::mctoll;

Function *RuntimeFunction::getOrCreateSecOffsetCalcFunction(Module &M) {
  std::string FuncName = "getRuntimeSectionOffset";
  Function *Func = M.getFunction(FuncName);

  if (Func == nullptr) {
    LLVMContext &Ctx(M.getContext());
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Value *Zero64BitValue = ConstantInt::get(Int64Ty, 0, false /* isSigned */);

    SmallVector<Type *, 4> ArgTypes = {
        Int64Ty /* RODAddr */,
        Int64Ty /* SecStAddr */,
        Int64Ty /*SecSize */,
        Int64Ty /* Runtime ROData GV */,
    };
    ArrayRef<Type *> ArgTypeVector(ArgTypes);

    FunctionType *FuncType =
        FunctionType::get(Int64Ty, ArgTypeVector, false /* isVarArg*/);

    // Create function
    Func =
        Function::Create(FuncType, GlobalValue::ExternalLinkage, FuncName, M);
    Func->setCallingConv(CallingConv::C);

    Function::arg_iterator Args = Func->arg_begin();
    Value *InAddr = Args++;
    InAddr->setName("InAddr");
    Value *SecBeg = Args++;
    SecBeg->setName("SecBeg");
    Value *SecSz = Args++;
    SecSz->setName("SecSz");
    Value *RTGV = Args++;
    RTGV->setName("RTGV");

    // Create the entry basic block
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Func);

    // %cmp = icmp uge i64, %InAddr, %SecBeg
    CmpInst *CmpBegin =
        ICmpInst::Create(Instruction::ICmp, CmpInst::Predicate::ICMP_UGE,
                         InAddr, SecBeg, "rodata-cmp-begin", BB);
    // %secEnd = add i64 %SecSz, %SecBeg
    Instruction *SecEnd =
        BinaryOperator::CreateAdd(SecSz, SecBeg, "rodata-sec-end", BB);

    // %cmpEnd = icmp ule i64 %InAddr, %SecEnd
    CmpInst *CmpEnd =
        ICmpInst::Create(Instruction::ICmp, CmpInst::Predicate::ICMP_ULE,
                         InAddr, SecEnd, "rodata-cmp-end", BB);

    // %inSec = and i1 %CmpBegin, %CmpEnd
    Instruction *InSec =
        BinaryOperator::CreateAnd(CmpBegin, CmpEnd, "rodata-cond", BB);

    // %offset = sub i64 %RTGV, %SecBeg
    Instruction *Offset =
        BinaryOperator::CreateSub(RTGV, SecBeg, "rodata-offset", BB);
    // %sel = select i1 %inSec, i64 Zero64BitValue, offset
    Instruction *Sel =
        SelectInst::Create(InSec, Offset, Zero64BitValue, "rodata-result", BB);
    ReturnInst::Create(Ctx, Sel, BB);
  }
  return Func;
}
