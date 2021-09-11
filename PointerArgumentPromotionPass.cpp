//===-- PointerArgumentPromotionPass.cpp ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "PointerArgumentPromotionPass.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"

#include <set>
#include <map>

char PointerArgumentPromotionPass::ID = 0;


/*
  If an integer argument is always used in inttoptr instructions,
  replace it with a pointer argument.
  Adjust all calls to this function to properly use the pointer arguments.
  Raising the level of abstraction has the benefit of enabling better code
  analysis and further optimizations.
*/
static bool ReplacePtrArguments(Function *F) {
  std::map<Argument*, Type*> ArgPtrTy;

  for (Argument &A : F->args()) {
    bool IsInt2Ptr = true;
    std::set<Type*> Types;
    for (User *U : A.users()) {
      IsInt2Ptr = IsInt2Ptr && (isa<IntToPtrInst>(U) || isa<ReturnInst>(U));
      IntToPtrInst *I2P = dyn_cast<IntToPtrInst>(U);
      if (I2P) {
        Types.insert(I2P->getType());
      }
    }
    if (IsInt2Ptr && Types.size()>=1) {
      Type *PtrTy = *Types.begin();
      if (Types.size()>1) {
        PtrTy = PointerType::getUnqual(IntegerType::get(F->getContext(),8));
      }

      ArgPtrTy[&A] = PtrTy;
    }
  }

  Type *RetTy = F->getReturnType();
  if (!F->getReturnType()->isVoidTy()) {
    std::set<Type*> RetTypes;
    for (Instruction &I : instructions(F)) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(&I)) {
	Argument *ArgOp = dyn_cast<Argument>(RI->getOperand(0));
        if ( ArgOp && ArgPtrTy.find(ArgOp)!=ArgPtrTy.end() ) {
          RetTypes.insert( ArgPtrTy[ArgOp] );
	} else {
	  RetTypes.clear();
	  break;
	}
      }
    }
    if (!RetTypes.empty()) {
      if (RetTypes.size()==1) {
        RetTy = *RetTypes.begin();
      } else {
        RetTy = PointerType::getUnqual(IntegerType::get(F->getContext(),8));
      }
    }
  }


  //If there are arguments for promotion
  if (!ArgPtrTy.empty()) {
    
    std::vector<Argument *> OldArgsList;

    std::vector<Type *> NewArgs;
    for (Argument &A : F->args()) {
      OldArgsList.push_back(&A);
      if (ArgPtrTy.find(&A)!=ArgPtrTy.end()) {
        NewArgs.push_back( ArgPtrTy[&A] );
      } else 
        NewArgs.push_back( A.getType() );
    }
    ArrayRef<Type *> NewArgTypes(NewArgs);

    FunctionType *NFTy = FunctionType::get(RetTy, NewArgTypes, false);

    Function *NF = Function::Create(NFTy, F->getLinkage());

    NF->copyAttributesFrom(F);

    if (F->getAlignment())
      NF->setAlignment(Align(F->getAlignment()));
    NF->setCallingConv(F->getCallingConv());
    NF->setLinkage(F->getLinkage());
    NF->setDSOLocal(F->isDSOLocal());
    NF->setSubprogram(F->getSubprogram());
    NF->setUnnamedAddr(F->getUnnamedAddr());
    NF->setVisibility(F->getVisibility());
    if (F->hasPersonalityFn())
      NF->setPersonalityFn(F->getPersonalityFn());
    if (F->hasComdat())
      NF->setComdat(F->getComdat());
    if (F->hasSection())
      NF->setSection(F->getSection());

    F->getParent()->getFunctionList().insert(F->getIterator(), NF);
    NF->takeName(F);

    // Since we have now created the new function, splice the body of the old
    // function right into the new function, leaving the old rotting hulk of the
    // function empty.
    NF->getBasicBlockList().splice(NF->begin(), F->getBasicBlockList());

    std::vector<Argument *> NewArgsList;
    for (Argument &arg : NF->args()) {
      NewArgsList.push_back(&arg);
    }

    // Loop over the argument list, transferring uses of the old arguments over to
    // the new arguments, also transferring over the names as well. 

    for (unsigned i = 0; i < NewArgsList.size(); i++) {
      if (ArgPtrTy.find(OldArgsList[i])!=ArgPtrTy.end()) {
        for (auto It = OldArgsList[i]->user_begin(); It!=OldArgsList[i]->user_end();) {
          User *U = *It;
          It++;
          if (auto *I2P = dyn_cast<IntToPtrInst>(U)) {
            IRBuilder<> Builder(I2P);
            auto *CastPtr = Builder.CreatePointerCast(NewArgsList[i], I2P->getType());
            I2P->replaceAllUsesWith(CastPtr);
            I2P->eraseFromParent();
          } else if (auto *RI = dyn_cast<ReturnInst>(U)) {
            IRBuilder<> Builder(RI);
            if (RetTy->isPointerTy())
              RI->setOperand(0,Builder.CreatePointerCast(NewArgsList[i], RetTy));
            else
              RI->setOperand(0,Builder.CreatePtrToInt(NewArgsList[i], RetTy));
          } else {
            assert(false && "Unexpected instruction");
          }
        }
      } else
        OldArgsList[i]->replaceAllUsesWith(NewArgsList[i]);

      NewArgsList[i]->takeName(OldArgsList[i]);
    }

    // Clone metadatas from the old function, including debug info descriptor.
    SmallVector<std::pair<unsigned, MDNode *>, 1> MDs;
    F->getAllMetadata(MDs);
    for (auto MD : MDs)
      NF->addMetadata(MD.first, *MD.second);

    for (auto It = F->user_begin(); It!=F->user_end();) {
      User *U = *It;
      It++;

      if (auto *CB = dyn_cast<CallBase>(U)) {
        IRBuilder<> Builder(CB);

        std::vector<Value*> Args;
        for (unsigned i = 0; i<CB->getNumArgOperands(); i++) {
          if (i<OldArgsList.size() && ArgPtrTy.find(OldArgsList[i])!=ArgPtrTy.end()) {
            if (auto *P2I = dyn_cast<PtrToIntInst>(CB->getArgOperand(i))) {
              Args.push_back(  Builder.CreatePointerCast(P2I->getOperand(0), ArgPtrTy[OldArgsList[i]]) );
            } else {
              Args.push_back(  Builder.CreateIntToPtr(CB->getArgOperand(i), ArgPtrTy[OldArgsList[i]]) );
            }
          } else Args.push_back( CB->getArgOperand(i) );
        }

        CallBase *NewCB = nullptr;
        if (CB->getOpcode() == Instruction::Call) {
          NewCB = (CallInst *)Builder.CreateCall( NF->getFunctionType(), NF, Args );
        } else if (CB->getOpcode() == Instruction::Invoke) {
          auto *II = dyn_cast<InvokeInst>(CB);
          NewCB = (InvokeInst *)Builder.CreateInvoke(NF->getFunctionType(),
                                                     NF, II->getNormalDest(),
                                                     II->getUnwindDest(), Args);
        } else {
          assert(false && "Unhandled call base instruction");
        }

        NewCB->setCallingConv(NF->getCallingConv());
        NewCB->setAttributes(NF->getAttributes());
        NewCB->setIsNoInline();

	if (CB->getType()!=NewCB->getType()) {
	  if ( CB->getType()->isPointerTy() ) {
	      CB->replaceAllUsesWith( Builder.CreatePointerCast(NewCB, CB->getType()) );
	  } else {
	      CB->replaceAllUsesWith( Builder.CreatePtrToInt(NewCB, CB->getType()) );
	  }
	} else CB->replaceAllUsesWith(NewCB);

        CB->eraseFromParent();
      }
    }
    F->replaceAllUsesWith(ConstantExpr::getBitCast(NF, F->getType()));
    
    // Delete the bitcast that we just created, so that NF does not
    // appear to be address-taken.
    NF->removeDeadConstantUsers();
    // Finally, nuke the old function.
    F->eraseFromParent();

    return true;
  }
  return false;
}

bool PointerArgumentPromotionPass::runOnModule(Module &M) {
  bool Changed = false;
  for (auto I = M.begin(); I!=M.end();) {
    Function *F = &*I;
    I++;
    Changed = Changed || ReplacePtrArguments(F);
  }

  return Changed;
}

void PointerArgumentPromotionPass::getAnalysisUsage(AnalysisUsage &AU) const {}
