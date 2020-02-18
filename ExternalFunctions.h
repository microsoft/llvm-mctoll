//===-- ExternalFunctions.h -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the table of known external functions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H
#define LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H

#include "ModuleRaiser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

class ExternalFunctions {
  ExternalFunctions(){};
  ~ExternalFunctions(){};

  typedef struct RetAndArgs_t {
    StringRef ReturnType;
    std::vector<StringRef> Arguments;
    bool isVariadic;
  } RetAndArgs;

public:
  static Function *Create(StringRef &CFuncName, ModuleRaiser &MR);
  // Table of known glibc function prototypes
  static const std::map<StringRef, ExternalFunctions::RetAndArgs>
      GlibcFunctions;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H
