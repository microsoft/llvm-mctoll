//===-- EmitRaisedOutputPass.cpp --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "EmitRaisedOutputPass.h"

char EmitRaisedOutputPass::ID = 0;

bool EmitRaisedOutputPass::runOnModule(Module &M) {
  ModuleAnalysisManager DummyMAM;
  // Save current data layout of the module
  auto DL = M.getDataLayout();
  // Set data layout to prevent emitting of architecture-specific information in
  // the output.
  M.setDataLayout("");
  // Call the appropriate printer
  switch (OutFileType) {
  case CGFT_AssemblyFile:
    PrintAsmPass.run(M, DummyMAM);
    break;
  case CGFT_ObjectFile:
    PrintBitCodePass.run(M, DummyMAM);
    break;
  case CGFT_Null:
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
