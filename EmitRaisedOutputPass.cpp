//===- EmitRaisedOutputPass.cpp - Binary raiser utility llvm-mctoll -----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of EmitRaisedOutputPass
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "EmitRaisedOutputPass.h"

char EmitRaisedOutputPass::ID = 0;

bool EmitRaisedOutputPass::runOnModule(Module &M) {
  ModuleAnalysisManager DummyMAM;
  // Save current data layout of the module
  auto DL = M.getDataLayout();
  // Set data layout to prevent emiting of architecture-specific information in
  // the output.
  M.setDataLayout("");
  // Call the appropriate printer
  switch (OutFileType) {
  case TargetMachine::CGFT_AssemblyFile:
    PrintAsmPass.run(M, DummyMAM);
    break;
  case TargetMachine::CGFT_ObjectFile:
    PrintBitCodePass.run(M, DummyMAM);
    break;
  case TargetMachine::CGFT_Null:
    // Do nothing - corresponds to the command line option
    // -output-format=null
    break;
  }
  // restore data layout information to the module.
  M.setDataLayout(DL);
  return false;
}

void EmitRaisedOutputPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
}
