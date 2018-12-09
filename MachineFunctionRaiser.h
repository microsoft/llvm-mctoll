//===-- MachineFunctionRaiser.h - Binary raiser utility llvm-mctoll -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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
#include "ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"

using namespace llvm;
using IndexedData32 = std::pair<uint64_t, uint32_t>;

class MachineFunctionRaiser {
public:
  MachineFunctionRaiser(Module &m, MachineFunction &mf, const ModuleRaiser *mr,
                        uint64_t start, uint64_t end)
      : MF(mf), module(m), MR(mr) {
    init(start, end);
    // The new MachineFunction is not in SSA form, yet
    MF.getProperties().reset(MachineFunctionProperties::Property::IsSSA);
  };

  bool runRaiserPasses();
  MachineFunction &getMachineFunction() const { return MF; }

  // Getters
  MCInstRaiser *getMCInstRaiser() { return mcInstRaiser; }
  Module &getModule() { return module; }
  MachineInstructionRaiser *getMachineInstrRaiser() {
    return machineInstRaiser;
  }
  void setMachineInstrRaiser(MachineInstructionRaiser *r) {
    machineInstRaiser = r;
  }
  Function *getRaisedFunction() {
    return machineInstRaiser->getRaisedFunction();
  }
  const ModuleRaiser *getModuleRaiser() { return MR; }

  // Cleanup orphaned empty basic blocks from raised function
  void cleanupRaisedFunction();

  virtual ~MachineFunctionRaiser() { delete mcInstRaiser; }

private:
  MachineFunction &MF;
  Module &module;

  // Data members built and used by this class
  MCInstRaiser *mcInstRaiser;
  MachineInstructionRaiser *machineInstRaiser;
  // A vector of data blobs found in the instruction stream
  // of this function. A data blob is a sequence of data bytes.
  // Multiple such data blobs may be found while disassembling
  // the instruction stream of a function symbol.
  std::vector<IndexedData32> dataBlobVector;
  const ModuleRaiser *MR;

  // Functions
  void init(uint64_t funcStart, uint64_t funcEnd);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_FUNCTIONRAISER_H
