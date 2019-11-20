//===-- EmitRaisedOutputPass.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of EmitRaisedOutputPass for use by
// llvm-mctoll. This class is provided to inhibit printing of target line
// and keep the resulting output architecture-neutral.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_EMITRAISEDOUTPUTPASS_H
#define LLVM_TOOLS_LLVM_MCTOLL_EMITRAISEDOUTPUTPASS_H

#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

class EmitRaisedOutputPass : public ModulePass {
  CodeGenFileType OutFileType;
  PrintModulePass PrintAsmPass;
  BitcodeWriterPass PrintBitCodePass;

public:
  static char ID;
  EmitRaisedOutputPass()
      : ModulePass(ID), OutFileType(CGFT_Null), PrintBitCodePass(dbgs()) {}
  EmitRaisedOutputPass(raw_ostream &OS, CodeGenFileType CGFT,
                       const std::string &Banner = "",
                       bool ShouldPreserveUseListOrder = false)
      : ModulePass(ID), OutFileType(CGFT),
        PrintAsmPass(OS, Banner, ShouldPreserveUseListOrder),
        PrintBitCodePass(OS, ShouldPreserveUseListOrder) {}

  bool runOnModule(Module &M) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_EMITRAISEDOUTPUTPASS_H
