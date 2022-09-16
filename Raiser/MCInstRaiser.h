//===-- MCInstRaiser.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H

#include "MCInstOrData.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Constants.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace llvm {
namespace mctoll {

// Class that encapsulates raising for MCInst vector to MachineInstrs
class MCInstRaiser {
public:
  using const_mcinst_iter = std::map<uint64_t, MCInstOrData>::const_iterator;

  MCInstRaiser(uint64_t Start, uint64_t End)
      : FuncStart(Start), FuncEnd(End), DataInCode(false){};

  void addTarget(uint64_t TargetIndex) {
    // Add targetIndex only if it falls within the function start and end
    if (!((TargetIndex >= FuncStart) && (TargetIndex <= FuncEnd)))
      return;
    TargetIndices.insert(TargetIndex);
  }

  void addMCInstOrData(uint64_t Index, MCInstOrData MCInst);

  void buildCFG(MachineFunction &MF, const MCInstrAnalysis *MIA,
                const MCInstrInfo *MII);

  std::set<uint64_t> getTargetIndices() const { return TargetIndices; }
  uint64_t getFuncStart() const { return FuncStart; }
  uint64_t getFuncEnd() const { return FuncEnd; }
  // Change the value of function end to a new value greater than current value
  bool adjustFuncEnd(uint64_t N);
  // Is Index in range of this function?
  bool isMCInstInRange(uint64_t Index) {
    return ((Index >= FuncStart) && (Index <= FuncEnd));
  }
  // Dump routine
  void dump() const;
  // Data in Code
  void setDataInCode(bool V) { DataInCode = V; }
  bool hasDataInCode() { return DataInCode; }

  // Get the MBB number that corresponds to MCInst at Offset.
  // MBB has the raised MachineInstr corresponding to MCInst at
  // Offset is the first instruction.
  // return -1 if no MBB maps to the specified MCinst offset
  int64_t getMBBNumberOfMCInstOffset(uint64_t Offset,
                                     MachineFunction &MF) const;

  // Get the MCInst at Offset that corresponds to MBB number .
  // MBB has the raised MachineInstr corresponding to MCInst at
  // Offset is the first instruction.
  // return -1 if no MCinst offset maps to the specified MBB
  int64_t getMCInstOffsetOfMBBNumber(uint64_t MBBNum) const;

  // Returns the iterator pointing to MCInstOrData at Offset in
  // input instruction stream.
  const_mcinst_iter getMCInstAt(uint64_t Offset) const {
    return InstMap.find(Offset);
  }

  const_mcinst_iter const_mcinstr_begin() const { return InstMap.begin(); }
  const_mcinst_iter const_mcinstr_end() const { return InstMap.end(); }

  // Get the size of instruction
  uint64_t getMCInstSize(uint64_t Offset) const;

  uint64_t getMCInstIndex(const MachineInstr &MI) const;

private:
  // NOTE: The following data structures are implemented to record instruction
  //       targets. Separate data structures are used instead of aggregating the
  //       target information to minimize the amount of memory allocated
  //       per instruction - given the ratio of control flow instructions is
  //       not high, in general. However, it is important to populate the target
  //       information during binary parse time AND is not duplicated.
  // A sequential list of source MCInsts or 32-bit data with corresponding index
  // Iteration over std::map contents is in non-descending order of keys. So,
  // the order in the map is guaranteed to be the order of instructions in the
  // insertion order i.e., code stream order.
  std::map<uint64_t, MCInstOrData> InstMap;
  // All targets recorded in a set to avoid duplicate entries
  std::set<uint64_t> TargetIndices;
  // A map of MCInst index, mci, to MachineBasicBlock number, mbbnum. The first
  // instruction of MachineBasicBlock number mbbnum is the MachineInstr
  // representation of the MCinst at the index, mci
  std::map<uint64_t, uint64_t> InstToMBBNum;

  std::map<uint64_t, std::vector<uint64_t>> MBBNumToMCInstTargetsMap;
  MachineInstr *RaiseMCInst(const MCInstrInfo &, MachineFunction &, MCInst,
                            uint64_t);
  // Start and End offsets of the array of MCInsts in mcInstVector
  uint64_t FuncStart;
  uint64_t FuncEnd;
  // Flag to indicate that the mcInstVector includes data (or uint32_ sized
  // quantities that the disassembler was unable to recognize as instructions
  // and are considered data
  bool DataInCode;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H
