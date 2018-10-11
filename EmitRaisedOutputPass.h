//===----------- EmitRaisedOutputPass.h -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

class EmitRaisedOutputPass : public ModulePass {
  TargetMachine::CodeGenFileType OutFileType;
  PrintModulePass PrintAsmPass;
  BitcodeWriterPass PrintBitCodePass;

public:
  static char ID;
  EmitRaisedOutputPass()
      : ModulePass(ID), OutFileType(TargetMachine::CGFT_Null),
        PrintBitCodePass(dbgs()) {}
  EmitRaisedOutputPass(raw_ostream &OS, TargetMachine::CodeGenFileType CGFT,
                       const std::string &Banner = "",
                       bool ShouldPreserveUseListOrder = false)
      : ModulePass(ID), OutFileType(CGFT),
        PrintAsmPass(OS, Banner, ShouldPreserveUseListOrder),
        PrintBitCodePass(OS, ShouldPreserveUseListOrder) {}

  bool runOnModule(Module &M) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_EMITRAISEDOUTPUTPASS_H
