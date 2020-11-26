//===-- ARMModuleRaiser.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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
  static bool classof(const ModuleRaiser *mr) {
    return mr->getArch() == Triple::arm;
  }
  ARMModuleRaiser() : ModuleRaiser() { Arch = Triple::arm; }

  // Create a new MachineFunctionRaiser object and add it to the list of
  // MachineFunction raiser objects of this module.
  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *f, const ModuleRaiser *mr,
                                    uint64_t start, uint64_t end) override;
  bool collectDynamicRelocations() override;

  void collectRodataInstAddr(uint64_t instAddr) {
    InstArgCollect.push_back(instAddr);
  }

  void fillInstArgMap(uint64_t rodataAddr, uint64_t argNum) {
    InstArgNumMap[rodataAddr] = argNum;
  }

  void fillInstAddrFuncMap(uint64_t callAddr, Function *func) {
    InstAddrFuncMap[callAddr] = func;
  }

  Function *getCallFunc(uint64_t callAddr) { return InstAddrFuncMap[callAddr]; }

  // Get function arg number.
  uint64_t getFunctionArgNum(uint64_t);

  // Accoring call instruction to get the rodata instruction addr.
  uint64_t getArgNumInstrAddr(uint64_t);
  // Method to map syscall.
  void setSyscallMapping(uint64_t idx, Function *fn) { SyscallMap[idx] = fn; }

  Function *getSyscallFunc(uint64_t idx) { return SyscallMap[idx]; }

  const Value *getRODataValueAt(uint64_t Offset) const;

  void addRODataValueAt(Value *V, uint64_t Offset) const;

private:
  // Commonly used data structures for ARM.
  // This is for call instruction. (BL instruction)
  DenseMap<uint64_t, Function *> InstAddrFuncMap;
  // Instruction address and function call arg number map.
  // <instruction address of first argument from, argument count>
  DenseMap<uint64_t, uint64_t> InstArgNumMap;
  // Collect instruction address about rodata.
  std::vector<uint64_t> InstArgCollect;
  // Map index to its corresponding function.
  std::map<uint64_t, Function *> SyscallMap;
  // Map of read-only data (i.e., from .rodata) to its corresponding global
  // value.
  // NOTE: A const version of ModuleRaiser object is constructed during the
  // raising process. Making this map mutable since this map is expected to be
  // updated throughout the raising process.
  mutable std::map<uint64_t, Value *> GlobalRODataValues;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMODULERAISER_H
