//===-- llvm-mctoll.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H
#define LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H

#include "llvm/DebugInfo/DIContext.h"
#include "llvm/Object/Archive.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/DataTypes.h"

namespace llvm {
class StringRef;

namespace object {
class COFFObjectFile;
class COFFImportFile;
class MachOObjectFile;
class ObjectFile;
class Archive;
class RelocationRef;
} // namespace object

extern cl::opt<std::string> TripleName;
extern cl::opt<std::string> ArchName;
extern cl::opt<std::string> FilterFunctionSet;
extern cl::list<std::string> FilterSections;
extern cl::opt<bool> Disassemble;
extern cl::opt<std::string> DisSymName;
extern cl::opt<bool> NonVerbose;
extern cl::opt<bool> SymbolTable;
extern cl::opt<bool> UnwindInfo;
extern cl::opt<bool> PrintImmHex;
extern cl::opt<DIDumpType> DwarfDumpType;

// Various helper functions.
void error(std::error_code ec);
void error(Error E);
bool isRelocAddressLess(object::RelocationRef A, object::RelocationRef B);
bool RelocAddressLess(object::RelocationRef a, object::RelocationRef b);
void parseInputMachO(StringRef Filename);
void printCOFFUnwindInfo(const object::COFFObjectFile *o);
void printMachOUnwindInfo(const object::MachOObjectFile *o);
void printELFFileHeader(const object::ObjectFile *o);
void printCOFFFileHeader(const object::ObjectFile *o);
void printCOFFSymbolTable(const object::COFFImportFile *i);
void printCOFFSymbolTable(const object::COFFObjectFile *o);
void printMachOFileHeader(const object::ObjectFile *o);
void printMachOLoadCommands(const object::ObjectFile *o);
void printWasmFileHeader(const object::ObjectFile *o);
void PrintSymbolTable(const object::ObjectFile *o, StringRef ArchiveName,
                      StringRef ArchitectureName = StringRef());
LLVM_ATTRIBUTE_NORETURN void error(Twine Message);
LLVM_ATTRIBUTE_NORETURN void report_error(StringRef File, Twine Message);
LLVM_ATTRIBUTE_NORETURN void report_error(Error E, StringRef File);
LLVM_ATTRIBUTE_NORETURN void
report_error(Error E, StringRef FileName, StringRef ArchiveName,
             StringRef ArchitectureName = StringRef());
LLVM_ATTRIBUTE_NORETURN void
report_error(Error E, StringRef ArchiveName, const object::Archive::Child &C,
             StringRef ArchitectureName = StringRef());

template <typename T, typename... Ts>
T unwrapOrError(Expected<T> EO, Ts &&... Args) {
  if (EO)
    return std::move(*EO);
  report_error(EO.takeError(), std::forward<Ts>(Args)...);
}

} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H
