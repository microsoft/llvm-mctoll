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
        {"malloc", {"i8*", {"i64"}, false}},
        {"memcpy", {"i8*", {"i8*", "i8*", "i64"}, false}},
        {"strcpy", {"i8*", {"i8*", "i8*"}, false}},
        {"__isoc99_scanf", {"i32", {"i8*"}, true}},
        {"time", {"i64", {"i64*"}, false}},
        {"puts", {"i32", {"i8*"}, false}},
        {"atoi", {"i32", {"i8*"}, false}}};

// Given the primitive type's string representation, return the Type*
// corresponding to it.
Type *ExternalFunctions::getPrimitiveType(const StringRef &TypeStr,
                                          LLVMContext &llvmCtx) {
  Type *retType = nullptr;
  if (TypeStr.equals("void")) {
    retType = Type::getVoidTy(llvmCtx);
  } else if (TypeStr.equals("i8")) {
    retType = Type::getInt8Ty(llvmCtx);
  } else if (TypeStr.equals("i16")) {
    retType = Type::getInt16Ty(llvmCtx);
  } else if (TypeStr.equals("i32")) {
    retType = Type::getInt32Ty(llvmCtx);
  } else if (TypeStr.equals("i64")) {
    retType = Type::getInt64Ty(llvmCtx);
  } else if (TypeStr.equals("i8*")) {
    retType = Type::getInt8PtrTy(llvmCtx);
  } else if (TypeStr.equals("i16*")) {
    retType = Type::getInt16PtrTy(llvmCtx);
  } else if (TypeStr.equals("i32*")) {
    retType = Type::getInt32PtrTy(llvmCtx);
  } else if (TypeStr.equals("i64*")) {
    retType = Type::getInt64PtrTy(llvmCtx);
  }
  assert((retType != nullptr) &&
         "Unsupported primitive type specified in known function prototype");
  return retType;
}

// Construct and return a Function* corresponding to a known glibc function.
Function *ExternalFunctions::Create(StringRef &CFuncName, Module &module) {
  Function *Func = nullptr;
  llvm::LLVMContext &llvmContext(module.getContext());
  FunctionType *FuncType = nullptr;
  auto iter = ExternalFunctions::GlibcFunctions.find(CFuncName);
  if (iter == ExternalFunctions::GlibcFunctions.end()) {
    errs() << CFuncName.data() << "\n";
    assert(false && "Unspported undefined function");
  }
  Func = module.getFunction(CFuncName);
  if (Func == nullptr) {
    const ExternalFunctions::RetAndArgs &retAndArgs = iter->second;
    Type *RetType =
        ExternalFunctions::getPrimitiveType(retAndArgs.ReturnType, llvmContext);
    std::vector<Type *> ArgVec;
    for (StringRef arg : retAndArgs.Arguments) {
      Type *argType = ExternalFunctions::getPrimitiveType(arg, llvmContext);
      ArgVec.push_back(argType);
    }
    ArrayRef<Type *> Args(ArgVec);
    FuncType = FunctionType::get(RetType, Args, retAndArgs.isVariadic);
    if (FuncType == nullptr) {
      errs() << CFuncName.data() << "\n";
      assert(false &&
             "Failed to construct function type for external function");
    }
    FunctionCallee FunCallee = module.getOrInsertFunction(CFuncName, FuncType);
    assert(isa<Function>(FunCallee.getCallee()) && "Expect Function");

    Func = reinterpret_cast<Function *>(FunCallee.getCallee());
    Func->setCallingConv(CallingConv::C);
    Func->setDSOLocal(true);
  }

  return Func;
}
