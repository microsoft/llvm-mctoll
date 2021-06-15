//===-- SimplifyPointerOperationPass.h --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of SimplifyPointerOperationPass for use by
// llvm-mctoll. This class raises the abstraction of memory address computations
// raised from binary. These operations are often raised as a series of integer
// operations alongside ptrtoint/intoptr instructions, which we replace by
// getelementptr instructions and simple pointer casting.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_SIMPLIFYPOINTEROPERATIONPASS_H
#define LLVM_TOOLS_LLVM_MCTOLL_SIMPLIFYPOINTEROPERATIONPASS_H

#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

class SimplifyPointerOperationPass : public FunctionPass {
public:
  static char ID;
  SimplifyPointerOperationPass()
      : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_SIMPLIFYPOINTEROPERATIONPASS_H
