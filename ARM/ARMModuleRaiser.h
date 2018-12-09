//===- ARMModuleRaiser.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMODULERAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMODULERAISER_H

#include "ModuleRaiser.h"

using namespace llvm;

class ARMModuleRaiser : public ModuleRaiser {
public:
  ARMModuleRaiser() : ModuleRaiser() { Arch = Triple::arm; }

  // Create a new MachineFunctionRaiser object and add it to the list of
  // MachineFunction raiser objects of this module.
  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *f, const ModuleRaiser *mr,
                                    uint64_t start, uint64_t end);
  bool collectDynamicRelocations();
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMODULERAISER_H
