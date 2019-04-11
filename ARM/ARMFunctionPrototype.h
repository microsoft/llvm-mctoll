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

#include "ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

/// ARMFunctionPrototype - This is used to discover function prototypes by
/// analyzing code of functions.
class ARMFunctionPrototype : public MachineFunctionPass {
public:
  ARMFunctionPrototype();
  virtual ~ARMFunctionPrototype();

  Function *discover(MachineFunction &mf);
  bool runOnMachineFunction(MachineFunction &mf);

  static char ID;

private:
  Type *getDefaultType() {
    return Type::getIntNTy(*CTX, MF->getDataLayout().getPointerSizeInBits());
  };
  /// isUsedRegiser - Check the first reference of the reg is USE.
  bool isUsedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// isDefinedRegiser - Check the first reference of the reg is DEF.
  bool isDefinedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// genParameterTypes - Get all arguments types of current MachineFunction.
  void genParameterTypes(std::vector<Type *> &paramTypes);
  /// genReturnType - Get return type of current MachineFunction.
  Type *genReturnType();

  bool PrintPass;
  MachineFunction *MF;
  LLVMContext *CTX;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMFUNCTIONPROTOTYPE_H
