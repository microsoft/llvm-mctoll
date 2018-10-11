//===-- ExternalFunctions.h - Binary raiser utility llvm-mctoll -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the ExternalFunction class
// and the table of known external functions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H
#define LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

class ExternalFunctions {
  ExternalFunctions(){};
  ~ExternalFunctions(){};

  typedef struct {
    StringRef ReturnType;
    std::vector<StringRef> Arguments;
    bool isVariadic;
  } RetAndArgs;

public:
  static Function *Create(StringRef &, Module &);
  static Type *getPrimitiveType(const StringRef &, LLVMContext &);
  // Table of known glibc function prototypes
  static const std::map<StringRef, ExternalFunctions::RetAndArgs>
      GlibcFunctions;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_EXTERNALFUNCTIONS_H
