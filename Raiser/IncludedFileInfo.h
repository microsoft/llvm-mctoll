//===-- IncludedFileInfo.h -------------------------------------*- C++ -*-===//
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

#ifndef LLVM_TOOLS_LLVM_MCTOLL_INCLUDEDFILEINFO_H
#define LLVM_TOOLS_LLVM_MCTOLL_INCLUDEDFILEINFO_H

#include "Raiser/ModuleRaiser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"


namespace llvm {
namespace mctoll {

class IncludedFileInfo {
  IncludedFileInfo(){};
  ~IncludedFileInfo(){};

public:
  typedef struct FunctionRetAndArgs_t {
    std::string ReturnType;
    std::vector<std::string> Arguments;
    bool isVariadic;
  } FunctionRetAndArgs;

  static Function *CreateFunction(StringRef &CFuncName, ModuleRaiser &MR);

  // Table of user specified function prototypes
  static std::map<std::string, IncludedFileInfo::FunctionRetAndArgs> ExternalFunctions;

  static std::set<std::string> ExternalVariables;

  static bool getExternalFunctionPrototype(std::vector<string> &FileNames,
                                           std::string &Target,
                                           std::string &SysRoot);

  static bool IsExternalVariable(std::string Name);
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_INCLUDEDFILEINFO_H
