//===-- ModuleRaiser.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MODULERAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_MODULERAISER_H

#include "FunctionFilter.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Target/TargetMachine.h"
#include <vector>

using namespace llvm;
using namespace std;
using namespace object;

namespace llvm {
namespace mctoll {

class MachineFunctionRaiser;
class MachineInstructionRaiser;

using JumpTableBlock = std::pair<ConstantInt *, MachineBasicBlock *>;

struct JumpTableInfo {
  /// The index of jump table in the function.
  unsigned jtIdx;

  /// The MachineBasicBlock which includes the jump table condition value.
  MachineBasicBlock *conditionMBB;

  /// The MachineBasicBlock which includes the default destination.
  MachineBasicBlock *df_MBB;
};

// The ModuleRaiser class encapsulates information needed to raise a given
// module.
class ModuleRaiser {
public:
  ModuleRaiser()
      : M(nullptr), TM(nullptr), MMI(nullptr), MIA(nullptr), MII(nullptr),
        Obj(nullptr), DisAsm(nullptr), TextSectionIndex(-1),
        Arch(Triple::ArchType::UnknownArch), FFT(nullptr), InfoSet(false) {}

  void setModuleRaiserInfo(Module *M, const TargetMachine *TM,
                           MachineModuleInfo *MMI, const MCInstrAnalysis *MIA,
                           const MCInstrInfo *MII, const ObjectFile *Obj,
                           MCDisassembler *DisAsm) {
    assert((InfoSet == false) &&
           "Module Raiser information can be set only once");
    this->M = M;
    this->TM = TM;
    this->MMI = MMI;
    this->MIA = MIA;
    this->MII = MII;
    this->Obj = Obj;
    this->DisAsm = DisAsm;
    this->FFT = new FunctionFilter(*M);
    InfoSet = true;
  }

  // Function to create a MachineFunctionRaiser corresponding to Function f.
  // As noted elsewhere (llvm-mctoll.cpp), f is a placeholder to allow for
  // creation of MachineFunction. The Function object representing raising
  // of MachineFunction is accessible by calling getRaisedFunction()
  // on the MachineFunctionRaiser object.
  virtual MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *F, const ModuleRaiser *,
                                    uint64_t Start, uint64_t End) = 0;

  MachineFunctionRaiser *getCurrentMachineFunctionRaiser() {
    if (mfRaiserVector.size() > 0)
      return mfRaiserVector.back();
    return nullptr;
  }

  // Insert the map of raised function R to place-holder function PH pointer
  // that inturn has the to corresponding MachineFunction.

  bool insertPlaceholderRaisedFunctionMap(Function *R, Function *PH) {
    auto V = PlaceholderRaisedFunctionMap.insert(std::make_pair(R, PH));
    return V.second;
  }

  bool collectTextSectionRelocs(const SectionRef &);
  virtual bool collectDynamicRelocations() = 0;

  MachineFunction *getMachineFunction(Function *);

  // Member getters
  Module *getModule() const { return M; }
  const TargetMachine *getTargetMachine() const { return TM; }
  MachineModuleInfo *getMachineModuleInfo() const { return MMI; }
  const MCInstrAnalysis *getMCInstrAnalysis() const { return MIA; }
  const MCInstrInfo *getMCInstrInfo() const { return MII; }
  const ObjectFile *getObjectFile() const { return Obj; }
  const MCDisassembler *getMCDisassembler() const { return DisAsm; }
  Triple::ArchType getArchType() { return Arch; }

  bool runMachineFunctionPasses();

  // Return the Function * corresponding to input binary function with
  // start offset equal to that specified as argument. This returns the pointer
  // to raised function, if one was constructed; else returns nullptr.
  Function *getRaisedFunctionAt(uint64_t) const;

  // Return the Function * corresponding to input binary function from
  // text relocation record with off set in the range [Loc, Loc+Size].
  Function *getCalledFunctionUsingTextReloc(uint64_t Loc, uint64_t Size) const;

  // Get dynamic relocation with offset 'O'
  const RelocationRef *getDynRelocAtOffset(uint64_t O) const;

  // Return text relocation of instruction at index 'I'. 'S' is the size of the
  // instruction at index 'I'.
  const RelocationRef *getTextRelocAtOffset(uint64_t I, uint64_t S) const;

  int64_t getTextSectionAddress() const;

  bool changeRaisedFunctionReturnType(Function *, Type *);
  virtual ~ModuleRaiser() {
    if (FFT != nullptr)
      delete FFT;
  }
  // Get the function filter for current Module.
  FunctionFilter *getFunctionFilter() const { return FFT; }
  // Get the current architecture type.
  Triple::ArchType getArch() const { return Arch; }

protected:
  // A sequential list of MachineFunctionRaiser objects created
  // as the instructions of the input binary are parsed. Each of
  // these correspond to a "machine function". A machine function
  // corresponds to a sequence of instructions (possibly interspersed
  // by data bytes) whose start is denoted by a function symbol in
  // the binary.
  std::vector<MachineFunctionRaiser *> mfRaiserVector;
  // A map of raised function pointer to place-holder function pointer
  // that links to the MachineFunction.
  DenseMap<Function *, Function *> PlaceholderRaisedFunctionMap;
  // Sorted vector of text relocations
  std::vector<RelocationRef> TextRelocs;
  // Vector of dynamic relocation records
  std::vector<RelocationRef> DynRelocs;

  // Commonly used data structures
  Module *M;
  const TargetMachine *TM;
  MachineModuleInfo *MMI;
  const MCInstrAnalysis *MIA;
  const MCInstrInfo *MII;
  const ObjectFile *Obj;
  MCDisassembler *DisAsm;
  // Index of text section whose instructions are raised
  int64_t TextSectionIndex;
  Triple::ArchType Arch;
  FunctionFilter *FFT;
  // Flag to indicate that fields are set. Resetting is not allowed/expected.
  bool InfoSet;
};

bool isSupportedArch(Triple::ArchType Arch);
ModuleRaiser *getModuleRaiser(const TargetMachine *TM);
void registerModuleRaiser(ModuleRaiser *M);

// error functions used from main and from raisers libs
extern StringRef ToolName;

void error(std::error_code EC);
void error(Error E);
[[noreturn]] void error(Twine Message);
[[noreturn]] void reportError(StringRef File, Twine Message);
[[noreturn]] void reportError(Error E, StringRef File);
[[noreturn]] void reportError(Error E, StringRef FileName,
                               StringRef ArchiveName,
                               StringRef ArchitectureName = StringRef());
[[noreturn]] void reportError(Error E, StringRef ArchiveName,
                               const object::Archive::Child &C,
                               StringRef ArchitectureName = StringRef());

template <typename T, typename... Ts>
T unwrapOrError(Expected<T> EO, Ts &&...Args) {
  if (EO)
    return std::move(*EO);
  reportError(EO.takeError(), std::forward<Ts>(Args)...);
}

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_MODULERAISER_H
