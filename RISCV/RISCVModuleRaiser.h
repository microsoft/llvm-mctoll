//===-- RISCVModuleRaiser.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of RISCV32ModuleRaiser and
// RISCV64ModuleRaiser classes for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_RISCV64_RISCV64MODULERAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_RISCV64_RISCV64MODULERAISER_H

#include "Raiser/ModuleRaiser.h"

namespace llvm {
namespace  mctoll {

class RISCV32ModuleRaiser : public ModuleRaiser {
public:
  // support LLVM-style RTTI dyn_cast
  static bool classof(const ModuleRaiser *MR) {
    return MR->getArch() == Triple::riscv32;
  }
  RISCV32ModuleRaiser() : ModuleRaiser() { Arch = Triple::riscv32; };

  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *F, const ModuleRaiser *MR,
                                    uint64_t Start, uint64_t End) override;
  bool collectDynamicRelocations() override;
};

class RISCV64ModuleRaiser : public ModuleRaiser {
public:
  // support LLVM-style RTTI dyn_cast
  static bool classof(const ModuleRaiser *MR) {
    return MR->getArch() == Triple::riscv64;
  }
  RISCV64ModuleRaiser() : ModuleRaiser() { Arch = Triple::riscv64; };

  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *F, const ModuleRaiser *MR,
                                    uint64_t Start, uint64_t End) override;
  bool collectDynamicRelocations() override;
};

} // end namespace mctoll
} // end namespace llvm

extern "C" void registerRISCV32ModuleRaiser();
extern "C" void registerRISCV64ModuleRaiser();
extern "C" void registerRISCVModuleRaiser();

#endif // LLVM_TOOLS_LLVM_MCTOLL_RISCV64_RISCV64MODULERAISER_H
