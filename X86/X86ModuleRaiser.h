//===- X86ModuleRaiser.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of X86ModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_X86_X86MODULERAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_X86_X86MODULERAISER_H

#include "ModuleRaiser.h"

using namespace llvm;

class X86ModuleRaiser : public ModuleRaiser {
public:
  static bool classof(const ModuleRaiser *mr) {
    return mr->getArch() == Triple::x86_64;
  }
  X86ModuleRaiser() : ModuleRaiser() { Arch = Triple::x86_64; };

  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *f, const ModuleRaiser *mr,
                                    uint64_t start, uint64_t end);
  bool collectDynamicRelocations();
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_X86_X86MODULERAISER_H
