//===-- ARMModuleRaiser.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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
