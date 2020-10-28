//===-- ExternalFunctions.cpp -----------------------------------*- C++ -*-===//
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

#include "ExternalFunctions.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"
#include <clang-c/Index.h>
#include <memory>
#include <sstream>
#include <string>

// NOTE: Not using namespace clang to highlight the fact that certain types such
// as Type being used in this file are from clang namespace and not from llvm
// namespace.

std::map<std::string, ExternalFunctions::RetAndArgs>
    ExternalFunctions::UserSpecifiedFunctions;

// FuncDeclVisitor

class FuncDeclVisitor : public clang::RecursiveASTVisitor<FuncDeclVisitor> {
  clang::SourceManager &SrcManager;

public:
  FuncDeclVisitor(clang::SourceManager &SM) : SrcManager(SM) {}

public:
  bool VisitFunctionDecl(clang::FunctionDecl *FuncDecl) {
    ExternalFunctions::RetAndArgs Entry;
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
    if (ExternalFunctions::UserSpecifiedFunctions.find(
            FuncDecl->getQualifiedNameAsString()) !=
        ExternalFunctions::UserSpecifiedFunctions.end()) {
      errs() << FuncDecl->getQualifiedNameAsString()
             << " : Ignoring duplicate entry in "
             << SrcManager.getFilename(FuncDecl->getLocation()) << "\n";
    } else {
      ExternalFunctions::UserSpecifiedFunctions.insert(
          std::pair<std::string, ExternalFunctions::RetAndArgs>(
              FuncDecl->getQualifiedNameAsString(), Entry));
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
      std::string TypeStr;
      const clang::BuiltinType *BltInTy = CurUnQTy->getAs<clang::BuiltinType>();
      switch (BltInTy->getKind()) {
      case clang::BuiltinType::Kind::Char_S:
      case clang::BuiltinType::Kind::Char_U:
      case clang::BuiltinType::Kind::UChar:
      case clang::BuiltinType::Kind::Bool:
        UnQTyStr.append("i8");
        break;
      case clang::BuiltinType::Kind::Short:
      case clang::BuiltinType::Kind::UShort:
        UnQTyStr.append("i16");
        break;
      case clang::BuiltinType::Kind::Int:
      case clang::BuiltinType::Kind::UInt:
      case clang::BuiltinType::Kind::Long:
      case clang::BuiltinType::Kind::ULong:
        UnQTyStr.append("i32");
        break;
      case clang::BuiltinType::Kind::LongLong:
      case clang::BuiltinType::Kind::ULongLong:
        UnQTyStr.append("i64");
        break;
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
      // Append any pointer qualifiers
      UnQTyStr.append(PointerStr);
    } else
      // If it is not a builtin type consider it to be an int64 type
      UnQTyStr.append("i64").append(PointerStr);
    return UnQTyStr;
  }
};

class FuncDeclFinder : public clang::ASTConsumer {
  clang::SourceManager &SourceManager;
  FuncDeclVisitor Visitor;

public:
  FuncDeclFinder(clang::SourceManager &SM) : SourceManager(SM), Visitor(SM) {}

  void HandleTranslationUnit(clang::ASTContext &Context) final {
    auto Decls = Context.getTranslationUnitDecl()->decls();
    for (auto &Decl : Decls) {
      if (!Decl->isFunctionOrFunctionTemplate())
        continue;
      const auto &FileID = SourceManager.getFileID(Decl->getLocation());
      if (FileID != SourceManager.getMainFileID())
        continue;
      clang::FunctionDecl *FuncDecl = Decl->getAsFunction();
      Visitor.TraverseFunctionDecl(FuncDecl);
    }
  }
};

class FuncDeclFindingAction : public clang::ASTFrontendAction {
public:
  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &CI, clang::StringRef) final {
    return std::unique_ptr<clang::ASTConsumer>(
        new FuncDeclFinder(CI.getSourceManager()));
  }
};

// Construct and return a Function* corresponding to a known external function
Function *ExternalFunctions::Create(StringRef &CFuncName, ModuleRaiser &MR) {
  Module *M = MR.getModule();
  assert(M != nullptr && "Uninitialized ModuleRaiser!");

  Function *Func = M->getFunction(CFuncName);
  if (Func != nullptr)
    return Func;

  auto iter = ExternalFunctions::UserSpecifiedFunctions.find(CFuncName.str());
  if (iter == ExternalFunctions::UserSpecifiedFunctions.end()) {
    errs() << "Unknown prototype for function : " << CFuncName.data() << "\n";
    errs() << "Use -I </full/path/to/file>, where /full/path/to/file declares "
              "its prototype\n";
    return nullptr;
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

bool ExternalFunctions::getUserSpecifiedFuncPrototypes(
    std::vector<std::string> &FileNames) {
  static llvm::cl::OptionCategory InclFileParseCategory("my-tool options");
  const int ToolArgc = 3; // 3 arguments viz., "dummy-tool IncludeFileName --"
  const char *ToolArgv[ToolArgc];
  ToolArgv[0] = "dummy-tool";
  ToolArgv[2] = "--";

  // Add each include file as second argument to parse it for function
  // declarations.
  for (auto FileName : FileNames) {
    // CommandOptionParser constructor can change the contents for its first
    // argument. reset it to ToolArgc in preparation for parsing the next
    // include file.
    int ArgSz = ToolArgc;
    ToolArgv[1] = FileName.c_str();
    clang::tooling::CommonOptionsParser OptParser(
        ArgSz, const_cast<const char **>(ToolArgv), InclFileParseCategory);
    clang::tooling::ClangTool Tool(OptParser.getCompilations(),
                                   OptParser.getSourcePathList());
    int Success = Tool.run(
        clang::tooling::newFrontendActionFactory<FuncDeclFindingAction>()
            .get());
    switch (Success) {
    case 0:
      break;
    default:
      // TODO : Expand
      dbgs() << "Error\n";
    }
  }
  return true;
}
