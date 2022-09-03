//===-- MachineFunctionRaiser.h ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the MachineFunctionRaiser class used
// by llvm-mctoll. This class encapsulates the context in which an assembly
// function is raised.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONRAISER_H

#include "MachineInstructionRaiser.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"

namespace llvm {
namespace mctoll {

using IndexedData32 = std::pair<uint64_t, uint32_t>;

class MachineFunctionRaiser {
public:
  MachineFunctionRaiser(Module &TheM, MachineFunction &TheMF, const ModuleRaiser *TheMR,
                        uint64_t Start, uint64_t End)
      : MF(TheMF), M(TheM), MachineInstRaiser(nullptr), MR(TheMR) {

    InstRaiser = new MCInstRaiser(Start, End);

    // The new MachineFunction is not in SSA form, yet
    MF.getProperties().reset(MachineFunctionProperties::Property::IsSSA);
  };

  virtual ~MachineFunctionRaiser() { delete InstRaiser; }

  bool runRaiserPasses();

  MachineFunction &getMachineFunction() const { return MF; }

  // Getters
  MCInstRaiser *getMCInstRaiser() { return InstRaiser; }

  Module &getModule() { return M; }

  MachineInstructionRaiser *getMachineInstrRaiser();

  void setMachineInstrRaiser(MachineInstructionRaiser *MIR) {
    MachineInstRaiser = MIR;
  }

  Function *getRaisedFunction();
  void setRaisedFunction(Function *);

  const ModuleRaiser *getModuleRaiser() { return MR; }

  // Cleanup orphaned empty basic blocks from raised function
  void cleanupRaisedFunction();

private:
  MachineFunction &MF;
  Module &M;

  // Data members built and used by this class
  MCInstRaiser *InstRaiser;
  MachineInstructionRaiser *MachineInstRaiser;
  // A vector of data blobs found in the instruction stream
  // of this function. A data blob is a sequence of data bytes.
  // Multiple such data blobs may be found while disassembling
  // the instruction stream of a function symbol.
  std::vector<IndexedData32> DataBlobVector;
  const ModuleRaiser *MR;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONRAISER_H
