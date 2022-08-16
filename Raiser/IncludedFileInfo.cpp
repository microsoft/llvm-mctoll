//===-- IncludedFileInfo.cpp -----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file builds the table of external functions prototypes from
// user-specified input via -I option.
//
//===----------------------------------------------------------------------===//

#include "IncludedFileInfo.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <clang-c/Index.h>
#include <memory>
#include <sstream>
#include <string>

#define DEBUG_TYPE "prototypes"

using namespace llvm::mctoll;

// NOTE: Not using namespace clang to highlight the fact that certain types such
// as Type being used in this file are from clang namespace and not from llvm
// namespace.

std::map<std::string, IncludedFileInfo::FunctionRetAndArgs>
    IncludedFileInfo::ExternalFunctions;

std::set<std::string> IncludedFileInfo::ExternalVariables;

// FuncDeclVisitor

class FuncDeclVisitor : public clang::RecursiveASTVisitor<FuncDeclVisitor> {
  clang::ASTContext &Context;

public:
  FuncDeclVisitor(clang::ASTContext &Context) : Context(Context) {
    llvm::setCurrentDebugType(DEBUG_TYPE);
  }

  bool VisitFunctionDecl(clang::FunctionDecl *FuncDecl) {
    IncludedFileInfo::FunctionRetAndArgs Entry;
    clang::QualType RetTy = FuncDecl->getDeclaredReturnType();
    Entry.ReturnType =
        getUnqualifiedTypeString(RetTy, FuncDecl->getASTContext());
    for (auto Param : FuncDecl->parameters()) {
      clang::QualType ParamTy = Param->getOriginalType();
      std::string ParamTyStr =
          getUnqualifiedTypeString(ParamTy, FuncDecl->getASTContext());
      Entry.Arguments.push_back(ParamTyStr);
    }
    Entry.isVariadic = FuncDecl->isVariadic();
    // TODO: Raising binaries compiled from C++ sources is not yet supported. C
    // does not support function overloading. So, for now, trivially check for
    // function name to detect duplicate function prototype specification. Need
    // to update this check to include argument types when support to raise C++
    // binary is added.
    if (IncludedFileInfo::ExternalFunctions.find(
            FuncDecl->getQualifiedNameAsString()) !=
        IncludedFileInfo::ExternalFunctions.end()) {
      LLVM_DEBUG(dbgs() << FuncDecl->getQualifiedNameAsString()
                        << " : Ignoring duplicate entry at "
                        << FuncDecl->getLocation().printToString(
                               Context.getSourceManager())
                        << "\n");
    } else {
      IncludedFileInfo::ExternalFunctions.insert(
          std::pair<std::string, IncludedFileInfo::FunctionRetAndArgs>(
              FuncDecl->getQualifiedNameAsString(), Entry));
      LLVM_DEBUG(dbgs() << FuncDecl->getQualifiedNameAsString()
                        << " : Entry found at "
                        << FuncDecl->getLocation().printToString(
                               Context.getSourceManager())
                        << "\n");
    }
    return true;
  }

private:
  std::string getUnqualifiedTypeString(clang::QualType &QTy,
                                       clang::ASTContext &ASTCtx) {
    std::string PointerStr;
    std::string UnQTyStr;
    clang::SplitQualType SplitCurQTy = QTy.split();
    // Get unqualified, de-sugared type
    const clang::Type *CurUnQTy = SplitCurQTy.Ty->getUnqualifiedDesugaredType();
    while (true) {
      if (CurUnQTy->isPointerType()) {
        PointerStr.append("*");
        // Get unqualified, de-sugared pointee type
        CurUnQTy = CurUnQTy->getPointeeType()
                       .split()
                       .Ty->getUnqualifiedDesugaredType();
      } else
        break;
    }

    // Construct type string corresponding to the buitl-in type
    if (CurUnQTy->isBuiltinType()) {
      const clang::BuiltinType *BltInTy = CurUnQTy->getAs<clang::BuiltinType>();
      if (BltInTy->isInteger()) {
        auto FieldInfo = ASTCtx.getTypeInfo(CurUnQTy);
        uint64_t TypeWidth = FieldInfo.Width;
        assert((TypeWidth == 64 || TypeWidth == 32 || TypeWidth == 16 ||
                TypeWidth == 8) &&
               "Unexpected builtin type width encountered");
        UnQTyStr.append("i" + to_string(TypeWidth));
      } else {
        switch (BltInTy->getKind()) {
        case clang::BuiltinType::Kind::Float:
          UnQTyStr.append("float");
          break;
        case clang::BuiltinType::Kind::Double:
          UnQTyStr.append("double");
          break;
        case clang::BuiltinType::Kind::LongDouble:
          UnQTyStr.append("ldouble");
          break;
        case clang::BuiltinType::Kind::Void:
          UnQTyStr.append("void");
          break;
        default:
          assert(false && "Unhandled builtin type found in include file");
        }
      }
      // Append any pointer qualifiers
      UnQTyStr.append(PointerStr);
    } else
      // If it is not a builtin type consider it to be an int64 type
      UnQTyStr.append("i64").append(PointerStr);
    return UnQTyStr;
  }
};

class FuncDeclFinder : public clang::ASTConsumer {
  FuncDeclVisitor Visitor;

public:
  FuncDeclFinder(clang::ASTContext &Context) : Visitor(Context) {}

  void HandleTranslationUnit(clang::ASTContext &Context) final {
    auto Decls = Context.getTranslationUnitDecl()->decls();
    // clang::SourceManager &SourceManager(Context.getSourceManager());
    for (auto &Decl : Decls) {
      if (Decl->isFunctionOrFunctionTemplate()) {
        // const auto &FileID = SourceManager.getFileID(Decl->getLocation());
        // if (FileID != SourceManager.getMainFileID())
        //   continue;
        clang::FunctionDecl *FuncDecl = Decl->getAsFunction();
        Visitor.TraverseFunctionDecl(FuncDecl);
      } else if (Decl->getKind() == clang::Decl::Kind::Var) {
        auto *VarDecl = dyn_cast<clang::VarDecl>(Decl);
        IncludedFileInfo::ExternalVariables.insert(
            VarDecl->getQualifiedNameAsString());
      }
    }
  }
};

class FuncDeclFindingAction : public clang::ASTFrontendAction {
public:
  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &CI,
                    clang::StringRef InFile) final {
    return std::unique_ptr<clang::ASTConsumer>(
        new FuncDeclFinder(CI.getASTContext()));
  }
};

// Construct and return a Function* corresponding to a known external function
Function *IncludedFileInfo::CreateFunction(StringRef &CFuncName,
                                           ModuleRaiser &MR) {
  Module *M = MR.getModule();
  assert(M != nullptr && "Uninitialized ModuleRaiser!");

  Function *Func = M->getFunction(CFuncName);
  if (Func != nullptr)
    return Func;

  auto iter = IncludedFileInfo::ExternalFunctions.find(CFuncName.str());
  if (iter == IncludedFileInfo::ExternalFunctions.end()) {
    errs() << "Unknown prototype for function : " << CFuncName.data() << "\n";
    errs() << "Use -I </full/path/to/file>, where /full/path/to/file declares "
              "its prototype\n";
    return nullptr;
  }

  const IncludedFileInfo::FunctionRetAndArgs &retAndArgs = iter->second;
  Type *RetType =
      MR.getFunctionFilter()->getPrimitiveDataType(retAndArgs.ReturnType);
  std::vector<Type *> ArgVec;
  for (StringRef arg : retAndArgs.Arguments) {
    Type *argType = MR.getFunctionFilter()->getPrimitiveDataType(arg);
    ArgVec.push_back(argType);
  }

  ArrayRef<Type *> Args(ArgVec);
  if (llvm::FunctionType *FuncType =
          FunctionType::get(RetType, Args, retAndArgs.isVariadic)) {
    FunctionCallee FunCallee = M->getOrInsertFunction(CFuncName, FuncType);
    assert(isa<Function>(FunCallee.getCallee()) && "Expect Function");
    Func = reinterpret_cast<Function *>(FunCallee.getCallee());
    Func->setCallingConv(CallingConv::C);
    Func->setDSOLocal(true);
    return Func;
  }

  errs() << CFuncName.data() << "\n";
  errs() << "Failed to construct external function's type for : "
         << CFuncName.data() << "\n";
  errs() << "Use -I </full/path/to/file>, where /full/path/to/file declares "
            "its prototype\n";
  return nullptr;
}

bool IncludedFileInfo::getExternalFunctionPrototype(
    std::vector<std::string> &FileNames, std::string &Target,
    std::string &SysRoot) {
  std::vector<const char *> ArgPtrVec;
  ArgPtrVec.push_back("parse-header-files");
  ArgPtrVec.push_back("--");

  if (llvm::DebugFlag)
    ArgPtrVec.push_back("-v");
  if (!Target.empty()) {
    ArgPtrVec.push_back("-target");
    ArgPtrVec.push_back(Target.c_str());
  }
  if (!SysRoot.empty()) {
    ArgPtrVec.push_back("--sysroot");
    ArgPtrVec.push_back(SysRoot.c_str());
  }

  auto *ToolArgv = ArgPtrVec.data();
  int ArgSz = ArgPtrVec.size();

  std::string ErrorMessage;
  std::unique_ptr<clang::tooling::CompilationDatabase> Compilations =
      clang::tooling::FixedCompilationDatabase::loadFromCommandLine(ArgSz, ToolArgv, ErrorMessage);
  if (!ErrorMessage.empty())
    llvm::errs() << ErrorMessage.append("\n");

  clang::tooling::ClangTool Tool(*Compilations, FileNames);
  int Success = Tool.run(
      clang::tooling::newFrontendActionFactory<FuncDeclFindingAction>().get());
  switch (Success) {
  case 0:
    break;
  default:
    // TODO : Expand
    dbgs() << "Error\n";
  }

  return true;
}

bool IncludedFileInfo::IsExternalVariable(std::string Name) {
  // If there is a suffix like stdout@@GLIBC_2.2.5, remove it to check
  // if the symbol is defined in a user-passed header file
  auto NameEnd = Name.find("@@");
  if (NameEnd != std::string::npos) {
    Name = Name.substr(0, NameEnd);
  }
  // Declare external global variables as external and don't initalize them
  return IncludedFileInfo::ExternalVariables.find(Name) !=
         IncludedFileInfo::ExternalVariables.end();
}

#undef DEBUG_TYPE
