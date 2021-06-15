//===-- SimplifyPointerOperationPass.cpp ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SimplifyPointerOperationPass.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

char SimplifyPointerOperationPass::ID = 0;

bool SimplifyPointerOperationPass::runOnFunction(Function &F) {
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (auto *I2P = dyn_cast<IntToPtrInst>(&I)) {
        Value *V = I2P->getOperand(0);
        if (auto *BinOp = dyn_cast<BinaryOperator>(V)) {
          auto *P2I = dyn_cast<PtrToIntInst>(BinOp->getOperand(0));
  
          if (P2I && (BinOp->getOpcode()==Instruction::Add || BinOp->getOpcode()==Instruction::Or)) {
             auto *Ptr = P2I->getOperand(0);
  
             auto *PtrElemTy = dyn_cast<PointerType>(Ptr->getType())->getElementType();
             if (isa<IntegerType>(PtrElemTy)) {
               Value *Idx = BinOp->getOperand(1);
               std::vector<Value*> GEPIdx;
               GEPIdx.push_back(Idx);

               IRBuilder<> Builder(&I);
	       auto *BytePtr = Builder.CreatePointerCast(Ptr, PointerType::getUnqual(IntegerType::get(F.getContext(),8)));

               auto *GEP = Builder.CreateGEP(BytePtr, GEPIdx);
  
               auto *FinalPtr = Builder.CreatePointerCast(GEP, I2P->getType());
               I2P->replaceAllUsesWith(FinalPtr);
             }
          }
        } else if (auto *P2I = dyn_cast<PtrToIntInst>(V)) {
          IRBuilder<> Builder(&I);
          auto *FinalPtr = Builder.CreatePointerCast(P2I->getOperand(0), I2P->getType());
          I2P->replaceAllUsesWith(FinalPtr);
        }
      }
    }
  }
  return true;
}

void SimplifyPointerOperationPass::getAnalysisUsage(AnalysisUsage &AU) const {}
