//===-- FunctionFilter.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the definition of FunctionFilter class that encapsulates
// user-specified function filters (include and exclude) of functions to be
// raised via the command line option --filter-functions-file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONFILTER_H
#define LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONFILTER_H

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"

namespace llvm {
namespace mctoll {

using namespace object;

/// Class encapsulating lists of function specifications to be included and
/// excluded along with methods to maintain and query the lists.
class FunctionFilter {
public:
  /// Filter types supported
  enum FilterType {
    FILTER_NONE,
    FILTER_EXCLUDE, // To be excluded.
    FILTER_INCLUDE  // To be included.
  };

  /// The function information which is used during raising call instructions.
  class FuncInfo {
  public:
    FuncInfo()
        : StartIdx(0), SymName(nullptr), FuncType(nullptr), Func(nullptr){};
    ~FuncInfo() {
      if (SymName == nullptr)
        delete SymName;
    };

    StringRef getSymName() const {
      assert(SymName != nullptr && "Uninitialized symbol name found!");
      StringRef Sym(*SymName);
      return Sym;
    };

    uint64_t StartIdx;      // The function start index.
    std::string *SymName;   // Symbol name.
    FunctionType *FuncType; // Function type.
    Function *Func;         // Pointer to the corresponding module function.
  };

  using FuncInfoVector = std::vector<FunctionFilter::FuncInfo *>;

  FunctionFilter() = delete;
  FunctionFilter(Module &Mod) : M(Mod){};
  ~FunctionFilter();
  /// Parse input string as symbol name and function type.
  bool parsePrototypeStr(StringRef &InProt, FuncInfo &OutProt);
  /// Get the function corresponding to the function prototype, if it exists;
  /// else create one add it to Module.
  Function *getOrCreateFunctionByPrototype(FuncInfo &Prot);
  /// Find function with symbol name in specified list type.
  FunctionFilter::FuncInfo *findFuncInfoBySymbol(StringRef &Sym,
                                                 FunctionFilter::FilterType FT);
  /// Find function with start index in the specified list type.
  Function *findFunctionByIndex(uint64_t StartIndex,
                                FunctionFilter::FilterType FT);
  /// Add a new function with given prototype to excluded function list.
  void addExcludedFunction(StringRef &PrototypeStr);
  /// Add a new function with given prototype to included function list.
  void addIncludedFunction(StringRef &PrototypeStr);
  /// Erase a function information from specified list type by symbol name.
  void eraseFunctionBySymbol(StringRef &Sym, FunctionFilter::FilterType FT);
  /// Get the data type corresponding to type string.
  Type *getPrimitiveDataType(const StringRef &TypeStr);
  /// Read user-specified include and exclude functions from file
  bool readFilterFunctionConfigFile(std::string &FunctionFilterFilename);
  /// Test if the list of specified list is empty.
  bool isFilterSetEmpty(FilterType);
  /// Check if function is needs raising.
  bool checkFunctionFilter(StringRef &PrototypeStr, uint64_t Start);
  /// Check if function is CRT function.
  bool isCRTFunction(const ObjectFile *Obj, StringRef &Sym);
  /// Dump the list of specified list; dump both include and exclude lists if no
  /// argument is specified.
  void dump(FilterType FT = FILTER_NONE);

private:
  /// Excluded function vector.
  FuncInfoVector ExcludedFunctionVector;
  /// Included function vector.
  FuncInfoVector IncludedFunctionVector;
  // Module associated with this class
  Module &M;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONFILTER_H
