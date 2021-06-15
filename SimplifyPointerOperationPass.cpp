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
    
    auto It = BB.begin();
    while (It!=BB.end()) {
      Instruction &I = *It;
      It++;

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

	       auto *BytePtrTy = PointerType::getUnqual(IntegerType::get(F.getContext(),8));
	       auto *BytePtr = Builder.CreatePointerCast(Ptr, BytePtrTy);

               auto *GEP = Builder.CreateGEP(BytePtr, GEPIdx);
  
               auto *FinalPtr = Builder.CreatePointerCast(GEP, I2P->getType());
               I2P->replaceAllUsesWith(FinalPtr);

               FinalPtr->takeName(I2P);
	       I2P->eraseFromParent();

	       if (BinOp->getNumUses()==0) BinOp->eraseFromParent();
	       if (P2I->getNumUses()==0) P2I->eraseFromParent();
             }
          }
        } else if (auto *P2I = dyn_cast<PtrToIntInst>(V)) {
          IRBuilder<> Builder(&I);
          auto *FinalPtr = Builder.CreatePointerCast(P2I->getOperand(0), I2P->getType());
          I2P->replaceAllUsesWith(FinalPtr);

	  FinalPtr->takeName(I2P);
	  I2P->eraseFromParent();
	  if (P2I->getNumUses()==0) P2I->eraseFromParent();
        }
      }
    }
  }
  return true;
}

void SimplifyPointerOperationPass::getAnalysisUsage(AnalysisUsage &AU) const {}
