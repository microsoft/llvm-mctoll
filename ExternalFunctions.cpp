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
    {"strcpy", {"i8*", {"i8*", "i8*"}, false}},
    {"__isoc99_scanf", {"i32", {"i8*"}, true}},
    {"time", {"i64", {"i64*"}, false}},
    {"puts", {"i32", {"i8*"}, false}},
    {"free", {"void", {"i8*"}, false}},
    {"atoi", {"i32", {"i8*"}, false}}
  };

// Return the Type* corresponding to a primitive type's string representation
Type *ExternalFunctions::getPrimitiveType(const StringRef &TypeStr,
                                          LLVMContext &Context) {
  if (TypeStr.equals("void"))
    return Type::getVoidTy(Context);
  if (TypeStr.equals("i8"))
    return Type::getInt8Ty(Context);
  if (TypeStr.equals("i16"))
    return Type::getInt16Ty(Context);
  if (TypeStr.equals("i32"))
    return Type::getInt32Ty(Context);
  if (TypeStr.equals("i64"))
    return Type::getInt64Ty(Context);
  if (TypeStr.equals("i8*"))
    return Type::getInt8PtrTy(Context);
  if (TypeStr.equals("i16*"))
    return Type::getInt16PtrTy(Context);
  if (TypeStr.equals("i32*"))
    return Type::getInt32PtrTy(Context);
  if (TypeStr.equals("i64*"))
    return Type::getInt64PtrTy(Context);
  
  llvm_unreachable("Unsupported primitive type in known function prototype");
}

// Construct and return a Function* corresponding to a known external function
Function *ExternalFunctions::Create(StringRef &CFuncName, Module &M) {
  llvm::LLVMContext &Context(M.getContext());

  auto iter = ExternalFunctions::GlibcFunctions.find(CFuncName);
  if (iter == ExternalFunctions::GlibcFunctions.end()) {
    errs() << CFuncName.data() << "\n";
    llvm_unreachable("Unsupported undefined function");
  }

  Function *Func = M.getFunction(CFuncName);
  if (Func != nullptr) 
    return Func;

  const ExternalFunctions::RetAndArgs &retAndArgs = iter->second;
  Type *RetType =
      ExternalFunctions::getPrimitiveType(retAndArgs.ReturnType, Context);
  std::vector<Type *> ArgVec;
  for (StringRef arg : retAndArgs.Arguments) {
    Type *argType = ExternalFunctions::getPrimitiveType(arg, Context);
    ArgVec.push_back(argType);
  }

  ArrayRef<Type *> Args(ArgVec);
  if (FunctionType *FuncType = 
      FunctionType::get(RetType, Args, retAndArgs.isVariadic)) {
    FunctionCallee FunCallee = M.getOrInsertFunction(CFuncName, FuncType);
    assert(isa<Function>(FunCallee.getCallee()) && "Expect Function");
    Func = reinterpret_cast<Function *>(FunCallee.getCallee());
    Func->setCallingConv(CallingConv::C);
    Func->setDSOLocal(true);
    return Func;
  }

  errs() << CFuncName.data() << "\n";
  llvm_unreachable("Failed to construct external function's type");
}
