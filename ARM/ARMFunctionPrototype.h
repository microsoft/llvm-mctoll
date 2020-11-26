//===-- ARMFunctionPrototype.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMFunctionPrototype class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H

#include "ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

/// This is used to discover function prototypes by analyzing code of functions.
class ARMFunctionPrototype : public MachineFunctionPass {
public:
  ARMFunctionPrototype();
  virtual ~ARMFunctionPrototype();

  Function *discover(MachineFunction &mf);
  bool runOnMachineFunction(MachineFunction &mf) override;

  static char ID;

private:
  Type *getDefaultType() {
    return Type::getIntNTy(*CTX, MF->getDataLayout().getPointerSizeInBits());
  };
  /// Check the first reference of the reg is USE.
  bool isUsedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Check the first reference of the reg is DEF.
  bool isDefinedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Get all arguments types of current MachineFunction.
  void genParameterTypes(std::vector<Type *> &paramTypes);
  /// Get return type of current MachineFunction.
  Type *genReturnType();

  MachineFunction *MF;
  LLVMContext *CTX;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H
