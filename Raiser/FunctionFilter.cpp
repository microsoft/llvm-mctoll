//===-- FunctionFilter.cpp --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of FunctionFilter class that
// encapsulates user-specified function filters (include and exclude) of
// functions to be raised via the command line option --filter-functions-file.
//
//===----------------------------------------------------------------------===//

#include "FunctionFilter.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Regex.h"
#include <fstream>

using namespace llvm;
using namespace llvm::mctoll;

FunctionFilter::~FunctionFilter() {
  if (!ExcludedFunctionVector.empty())
    for (auto *FIE : ExcludedFunctionVector)
      if (FIE != nullptr)
        delete FIE;

  if (!IncludedFunctionVector.empty())
    for (auto *FII : IncludedFunctionVector)
      if (FII != nullptr)
        delete FII;
}

/// Get the data type corresponding to type string. These correspond to type
/// strings generated in IncludedFileInfo.cpp upon parsing user specified
/// include files with external function prototypes.
Type *FunctionFilter::getPrimitiveDataType(const StringRef &TypeStr) {
  LLVMContext &CTX = M.getContext();
  Type *RetTy = nullptr;
  // Get the base type
  if (TypeStr.startswith("void"))
    RetTy = Type::getVoidTy(CTX);
  else if (TypeStr.startswith("i1"))
    RetTy = Type::getInt1Ty(CTX);
  else if (TypeStr.startswith("i8"))
    RetTy = Type::getInt8Ty(CTX);
  else if (TypeStr.startswith("i16"))
    RetTy = Type::getInt16Ty(CTX);
  else if (TypeStr.startswith("i32"))
    RetTy = Type::getInt32Ty(CTX);
  else if (TypeStr.startswith("i64"))
    RetTy = Type::getInt64Ty(CTX);
  else if (TypeStr.startswith("float"))
    RetTy = Type::getFloatTy(CTX);
  else if (TypeStr.startswith("double"))
    RetTy = Type::getDoubleTy(CTX);
  // most x86 compilers implement long double as 80-bit extension precision
  // type.
  // TODO : Exception MSVC long double is a synonym of double. Add the necessary
  // support when Windows binary support is implemented.
  else if (TypeStr.startswith("ldouble"))
    RetTy = Type::getX86_FP80Ty(CTX);

  assert((RetTy != nullptr) && "Invalid data type string!");
  // Is this a pointer type. Flatten out any T**** to just T*
  if (TypeStr.find_first_of("*") != std::string::npos) {
    // Special case void* to i8*. There is no Type::getVoidPtrTy()
    if (RetTy->isVoidTy())
      RetTy = Type::getInt8PtrTy(CTX);
    else
      RetTy = RetTy->getPointerTo();
  }
  return RetTy;
}

/// Parse input string as symbol name and function type.
bool FunctionFilter::parsePrototypeStr(StringRef &InProt,
                                       FunctionFilter::FuncInfo &OutProt) {
  SmallVector<StringRef, 4> Grp;
  Regex Rgx("(.+)[ ]+(.+)\\(([[:alnum:] \\*,]*)\\)");

  if (!Rgx.match(InProt, &Grp))
    return false;

  StringRef RetStr = Grp[1].trim();  // Get the return type string.
  StringRef SymName = Grp[2].trim(); // Get the symbol name string.
  StringRef Paras = Grp[3]; // Get the arguments' string. If no argument,
                            // it would be "".

  // Get the function return type.
  Type *RetTy = getPrimitiveDataType(RetStr);

  // Default variable argument is false.
  bool IsVari = false;
  // The set of arguments' date types.
  std::vector<Type *> ParamTypes;
  if (!Paras.empty()) {
    SmallVector<StringRef, 128> ParaVec;
    Paras.split(ParaVec, ',');
    for (SmallVector<StringRef, 128>::iterator I = ParaVec.begin(),
                                               E = ParaVec.end();
         I != E; ++I) {
      auto ParaStr = (*I).trim();
      // Skip void argument.
      if (ParaStr.lower() == "void")
        continue;
      // If found "..." in arguments' date type string, the current function
      // should have variable argument.
      if (ParaStr == "...") {
        IsVari = true;
        continue;
      }

      ParamTypes.push_back(getPrimitiveDataType(ParaStr));
    }
  }

  // Created function type.
  FunctionType *FnTy = FunctionType::get(RetTy, ParamTypes, IsVari);
  assert(FnTy != nullptr && "Failed to construct function type!");

  if (OutProt.SymName != nullptr)
    delete OutProt.SymName;
  OutProt.SymName = new std::string(SymName.str());
  OutProt.FuncType = FnTy;

  return true;
}

/// Get the module function corresponding to the function prototype, if it
/// exists; else create one add it to Module.
Function *
FunctionFilter::getOrCreateFunctionByPrototype(FunctionFilter::FuncInfo &Prot) {
  Function *Func = M.getFunction(Prot.getSymName());

  // Return the function with the specified function prototype, if one exists.
  if (Func != nullptr)
    return Func;

  // Create a new function and add it to Module.
  FunctionCallee FunCallee =
      M.getOrInsertFunction(Prot.getSymName(), Prot.FuncType);
  assert(isa<Function>(FunCallee.getCallee()) && "Expect a Function!");

  Func = reinterpret_cast<Function *>(FunCallee.getCallee());
  Func->setCallingConv(CallingConv::C);
  Func->setDSOLocal(true);

  return Func;
}

/// Add a new function with given prototype to excluded function list.
void FunctionFilter::addExcludedFunction(StringRef &PrototypeStr) {
  FunctionFilter::FuncInfo *FPT = new FunctionFilter::FuncInfo();
  assert(parsePrototypeStr(PrototypeStr, *FPT) &&
         "Invalid function prototype string!");
  Function *Funct = getOrCreateFunctionByPrototype(*FPT);
  FPT->StartIdx = 0;
  FPT->Func = Funct;
  ExcludedFunctionVector.push_back(FPT);

  StringRef Sym = FPT->getSymName();
  // Ensure that this function symbol is not in included list.
  if (IncludedFunctionVector.size() > 0 &&
      findFuncInfoBySymbol(Sym, FILTER_INCLUDE) != nullptr) {
    eraseFunctionBySymbol(Sym, FILTER_INCLUDE);
    dbgs() << "\nWarning: " << Sym << " is both in tables"
           << " exclude-functions and include-functions, it will not be"
           << " raised!\n";
  }
}

/// Add a new function with given prototype to included function list.
void FunctionFilter::addIncludedFunction(StringRef &PrototypeStr) {
  FunctionFilter::FuncInfo *FPT = new FunctionFilter::FuncInfo();
  assert(parsePrototypeStr(PrototypeStr, *FPT) &&
         "Invalid function prototype string!");
  StringRef Sym = FPT->getSymName();
  // Check if this function symbol is in the excluded set. Flag and error
  // otherwise.
  if (ExcludedFunctionVector.size() > 0 &&
      findFuncInfoBySymbol(Sym, FILTER_EXCLUDE) != nullptr) {
    dbgs() << "\n***** Warning: Found " << Sym << " both in "
           << " exclude-functions and include-functions. Considering it to be "
              "an excluded function\n";

    return;
  }

  FPT->StartIdx = 0;
  FPT->Func = nullptr;
  IncludedFunctionVector.push_back(FPT);
}

/// Find function with symbol name in specified list type.
FunctionFilter::FuncInfo *
FunctionFilter::findFuncInfoBySymbol(StringRef &Sym,
                                     FunctionFilter::FilterType FT) {
  FuncInfoVector FunctionVec;
  if (FT == FILTER_INCLUDE)
    FunctionVec = IncludedFunctionVector;
  else if (FT == FILTER_EXCLUDE)
    FunctionVec = ExcludedFunctionVector;
  else
    assert(false && "Unsupported filter type specified");

  for (auto *F : FunctionVec) {
    if (F->getSymName() == Sym)
      return F;
  }

  return nullptr;
}

/// Find function with start index in the specified list type.
Function *FunctionFilter::findFunctionByIndex(uint64_t StartIndex,
                                              FunctionFilter::FilterType FT) {
  FuncInfoVector *FuncVec = nullptr;
  if (FT == FILTER_INCLUDE)
    FuncVec = &IncludedFunctionVector;
  else if (FT == FILTER_EXCLUDE)
    FuncVec = &ExcludedFunctionVector;
  else
    assert(false && "Unsupported filter type specified");

  assert(FuncVec != nullptr && "Unexpected null function vector");

  for (auto *F : *FuncVec) {
    if (F->StartIdx == StartIndex)
      return F->Func;
  }

  return nullptr;
}

/// Erase a function information from specified list type by symbol name.
void FunctionFilter::eraseFunctionBySymbol(StringRef &Sym,
                                           FunctionFilter::FilterType FT) {
  FuncInfoVector *FuncVec;
  if (FT == FILTER_INCLUDE)
    FuncVec = &IncludedFunctionVector;
  else if (FT == FILTER_EXCLUDE)
    FuncVec = &ExcludedFunctionVector;
  else
    assert(false && "Unsupported filter type specified");

  assert(FuncVec != nullptr && "Unexpected null function vector");

  for (FunctionFilter::FuncInfoVector::iterator I = FuncVec->begin(),
                                                E = FuncVec->end();
       I != E; ++I) {
    auto *EM = *I;
    if (EM != nullptr && EM->getSymName() == Sym) {
      FuncVec->erase(I);
      delete EM;
      return;
    }
  }
}

/// Read the function symbol set from the configuration file of filter
/// functions.
bool FunctionFilter::readFilterFunctionConfigFile(
    std::string &FunctionFilterFilename) {

  if (FunctionFilterFilename.size() == 0)
    return false;

  std::ifstream F;
  F.open(FunctionFilterFilename);
  if (!F.is_open()) {
    dbgs() << "Warning: Can not read the configuration file of filter "
              "function set!!!";
    return false;
  }

  FunctionFilter::FilterType FFType = FunctionFilter::FILTER_NONE;
  char Buf[512];
  while (!F.eof()) {
    F.getline(Buf, 512);
    StringRef RawLine(Buf);
    StringRef Line = RawLine.trim();
    // Ignore comment line
    if (Line.startswith(";"))
      continue;
    if (FFType != FunctionFilter::FILTER_NONE) {
      SmallVector<StringRef, 3> Grp;
      // Match function information line, it looks like
      // "binary-name-1:function-1-prototype"
      Regex RgxEI("(.+):(.+)");
      if (RgxEI.match(Line, &Grp)) {
        assert(Grp.size() < 4 && "Only can match two elements in a line!!!");

        if (Grp[1].equals(sys::path::filename(M.getSourceFileName()))) {
          if (FFType == FunctionFilter::FILTER_EXCLUDE) {
            addExcludedFunction(Grp[2]);
          } else if (FFType == FunctionFilter::FILTER_INCLUDE) {
            addIncludedFunction(Grp[2]);
          } else {
            assert(false && "Unexpected function filter type");
          }
          continue;
        }
      }

      // Match the end of information block.
      Regex RgxEnd("\\}");
      if (RgxEnd.match(Line)) {
        FFType = FunctionFilter::FILTER_NONE;
        continue;
      }
    }

    // Match the start of exclude function information block.
    Regex RgxEnc("exclude-functions[ ]+\\{");
    if (RgxEnc.match(Line)) {
      FFType = FunctionFilter::FILTER_EXCLUDE;
      continue;
    }

    // Match the start of include function information block.
    Regex RgxInc("include-functions[ ]+\\{");
    if (RgxInc.match(Line)) {
      FFType = FunctionFilter::FILTER_INCLUDE;
      continue;
    }
  }
  // Close function filter configuration file
  F.close();
  return true;
}

// Test if the list of specified type is empty
bool FunctionFilter::isFilterSetEmpty(FilterType FT) {
  FuncInfoVector FunctionSet;
  if (FT == FILTER_INCLUDE)
    return IncludedFunctionVector.empty();
  if (FT == FILTER_EXCLUDE)
    return ExcludedFunctionVector.empty();

  llvm_unreachable_internal("Unexpected function filter type specified");
}

/// Dump the list of specified list; dump both include and exclude lists if no
/// argument is specified.
void FunctionFilter::dump(FilterType FT) {
  if ((FT == FILTER_NONE) || (FT == FILTER_INCLUDE)) {
    dbgs() << "Included functions\n";
    std::for_each(IncludedFunctionVector.begin(), IncludedFunctionVector.end(),
                  [](const FunctionFilter::FuncInfo *FFI) {
                    dbgs() << FFI->getSymName() << " ";
                  });
  }

  if ((FT == FILTER_NONE) || (FT == FILTER_EXCLUDE)) {
    dbgs() << "Excluded functions\n";
    std::for_each(ExcludedFunctionVector.begin(), ExcludedFunctionVector.end(),
                  [](const FunctionFilter::FuncInfo *FFI) {
                    dbgs() << FFI->getSymName() << " ";
                  });
  }
}
