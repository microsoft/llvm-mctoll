//===-- PointerArgumentPromotionPass.h --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_POINTERARGUMENTPROMOTIONPASS_H
#define LLVM_TOOLS_LLVM_MCTOLL_POINTERARGUMENTPROMOTIONPASS_H

#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

class PointerArgumentPromotionPass : public ModulePass {
public:
  static char ID;
  PointerArgumentPromotionPass()
      : ModulePass(ID) {}

  bool runOnModule(Module &M) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_POINTERARGUMENTPROMOTIONPASS_H
