//===- ARMFunctionPrototype.h -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMFunctionPrototype class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

class ARMFunctionPrototype : public MachineFunctionPass {
public:
  static char ID;

  ARMFunctionPrototype();
  virtual ~ARMFunctionPrototype();

  Function *discover(MachineFunction &mf);
  bool runOnMachineFunction(MachineFunction &mf);

private:
  bool PrintPass;

  /// Check the first reference of the reg is USE.
  bool isUsedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Check the first reference of the reg is DEF.
  bool isDefinedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Get all arguments types of current MachineFunction.
  void genParameterTypes(std::vector<Type *> &paramTypes,
                         const MachineFunction &mf, LLVMContext &ctx);
  /// Get return type of current MachineFunction.
  Type *genReturnType(const MachineFunction &mf, LLVMContext &ctx);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H
