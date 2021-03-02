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

public:
  typedef struct RetAndArgs_t {
    std::string ReturnType;
    std::vector<std::string> Arguments;
    bool isVariadic;
  } RetAndArgs;

  static Function *Create(StringRef &CFuncName, ModuleRaiser &MR);
  // Table of user specified function prototypes
  static std::map<std::string, ExternalFunctions::RetAndArgs>
      UserSpecifiedFunctions;
  static bool getUserSpecifiedFuncPrototypes(std::vector<string> &FileNames,
                                             std::string &CompDBDir);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H
