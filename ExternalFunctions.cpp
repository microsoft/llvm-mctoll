//===-- ExternalFunctions.cpp -----------------------------------*- C++ -*-===//
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

#include "ExternalFunctions.h"

const std::map<StringRef, ExternalFunctions::RetAndArgs>
    ExternalFunctions::GlibcFunctions = {
        {"printf", {"i32", {"i8*"}, true}},
        {"__printf_chk", {"i32", {"i8*"}, true}},
        {"malloc", {"i8*", {"i64"}, false}},
        {"memcpy", {"i8*", {"i8*", "i8*", "i64"}, false}},
        {"memset", {"i8*", {"i8*", "i32", "i64"}, false}},
        {"strcpy", {"i8*", {"i8*", "i8*"}, false}},
        {"strncpy", {"i8*", {"i8*", "i8*", "i64"}, false}},
        {"__isoc99_scanf", {"i32", {"i8*"}, true}},
        {"clock_gettime", {"i32", {"i64", "i64*"}, false}},
        {"time", {"i64", {"i64*"}, false}},
        {"sleep", {"i32", {"i32"}, false}},
        {"putchar", {"i32", {"i32"}, false}},
        {"puts", {"i32", {"i8*"}, false}},
        {"free", {"void", {"i8*"}, false}},
        {"atoi", {"i32", {"i8*"}, false}},
        {"exit", {"void", {"i32"}, false}}};

// Construct and return a Function* corresponding to a known external function
Function *ExternalFunctions::Create(StringRef &CFuncName, ModuleRaiser &MR) {
  Module *M = MR.getModule();
  assert(M != nullptr && "Uninitialized ModuleRaiser!");

  Function *Func = M->getFunction(CFuncName);
  if (Func != nullptr)
    return Func;

  auto iter = ExternalFunctions::GlibcFunctions.find(CFuncName);
  if (iter == ExternalFunctions::GlibcFunctions.end()) {
    errs() << CFuncName.data() << "\n";
    llvm_unreachable("Unsupported undefined function");
  }

  const ExternalFunctions::RetAndArgs &retAndArgs = iter->second;
  Type *RetType =
      MR.getFunctionFilter()->getPrimitiveDataType(retAndArgs.ReturnType);
  std::vector<Type *> ArgVec;
  for (StringRef arg : retAndArgs.Arguments) {
    Type *argType = MR.getFunctionFilter()->getPrimitiveDataType(arg);
    ArgVec.push_back(argType);
  }

  ArrayRef<Type *> Args(ArgVec);
  if (FunctionType *FuncType =
          FunctionType::get(RetType, Args, retAndArgs.isVariadic)) {
    FunctionCallee FunCallee = M->getOrInsertFunction(CFuncName, FuncType);
    assert(isa<Function>(FunCallee.getCallee()) && "Expect Function");
    Func = reinterpret_cast<Function *>(FunCallee.getCallee());
    Func->setCallingConv(CallingConv::C);
    Func->setDSOLocal(true);
    return Func;
  }

  errs() << CFuncName.data() << "\n";
  llvm_unreachable("Failed to construct external function's type");
}
