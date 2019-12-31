//===-- RuntimeCall.h ----------------*- C++ ----------------------------*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of functions that generate LLVM IR
// functions as part of raised code. The LLVM IR functions generated per-module
// and are called as needed in the raised code.
//
//===----------------------------------------------------------------------===//

#ifndef TOOLS_LLVM_MCTOLL_RUNTIMEFUNCTION_H_
#define TOOLS_LLVM_MCTOLL_RUNTIMEFUNCTION_H_

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

class RuntimeFunction {

public:
  // This function creates an LLVM IR function, if it is not already created,
  // adds it to module M and returns a pointer to it. The LLVM IR Function
  // returned has the following prototype:
  //     getRuntimeSectionOffset(int64_t SecAddr, int64_t SecStartAddr,
  //                             int64_t SecSize, int64_t RaisedGV)
  // where SecAddr - the address value to be potentially relocated at runtime of
  //                 the raised binary
  //     SecStartAddr - Value of section address start in source binary
  //     SecSize      - Size of section in source binary
  //     RaisedGV     - inttoptr converted value corresponding to the abstracted
  //                    representation as global variable of SecStart.
  // The generated function is currently used to obtain the offset of rodata
  // section addresses. So, RaisedGV is the corresponding intotoptr cast value
  // of global variable rodata_<n>, where n is the section number, that
  // represents the contents of .rodata section as a byte array.

  static Function *getOrCreateSecOffsetCalcFunction(Module &M);
};
#endif /* TOOLS_LLVM_MCTOLL_RUNTIMEFUNCTION_H_ */
