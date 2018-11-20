//===---- MCInstRaiser.h - Binary raiser utility llvm-mctoll --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of MCInstRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H

#include "MCInstOrData.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include <map>
#include <set>
#include <utility>
#include <vector>

using namespace llvm;

// Class that encapsulates raising for MCInst vector to MachineInstrs
class MCInstRaiser {
public:
  using const_mcinst_iter = std::map<uint64_t, MCInstOrData>::const_iterator;

  MCInstRaiser(uint64_t fStart, uint64_t fEnd)
      : FuncStart(fStart), FuncEnd(fEnd), dataInCode(false){};
  void addTarget(uint64_t targetIndex) {
    // Add targetIndex only if it falls within the function start and end
    if (!((targetIndex >= FuncStart) && (targetIndex <= FuncEnd))) {
      errs() << "*** WARNING Out of range target not added.\n";
      return;
    }
    targetIndices.insert(targetIndex);
  }
  void addMCInstOrData(uint64_t index, MCInstOrData mcInst);

  void buildCFG(MachineFunction &MF, const MCInstrAnalysis *mia,
                const MCInstrInfo *mii);

  std::set<uint64_t> getTargetIndices() const { return targetIndices; }
  uint64_t getFuncStart() const { return FuncStart; }
  uint64_t getFuncEnd() const { return FuncEnd; }
  // Change the value of function end to a new value greater than current value
  bool adjustFuncEnd(uint64_t n);
  // Is Index in range of this function?
  bool isMCInstInRange(uint64_t Index) {
    return ((Index >= FuncStart) && (Index <= FuncEnd));
  }
  // Dump routine
  void dump() const;
  // Data in Code
  void setDataInCode(bool v) { dataInCode = v; }
  bool hasDataInCode() { return dataInCode; }

  // Get the MBB number that corresponds to MCInst at Offset.
  // MBB has the raised MachineInstr corresponding to MCInst at
  // Offset is the first instruction.
  // return -1 if no MBB maps to the specified MCinst offset
  int64_t getMBBNumberOfMCInstOffset(uint64_t Offset) const {
    auto iter = mcInstToMBBNum.find(Offset);
    if (iter != mcInstToMBBNum.end()) {
      return (*iter).second;
    }
    return -1;
  }

  // Returns the iterator pointing to MCInstOrData at Offset in
  // input instruction stream.
  const_mcinst_iter getMCInstAt(uint64_t Offset) const {
    return mcInstMap.find(Offset);
  }

  const_mcinst_iter const_mcinstr_end() const { return mcInstMap.end(); }
  // Get the size of instruction
  uint64_t getMCInstSize(uint64_t Offset) const {
    const_mcinst_iter iter = mcInstMap.find(Offset);
    const_mcinst_iter end = mcInstMap.end();
    uint64_t InstSize = 0;
    assert(iter != end && "Attempt to find MCInst at non-existent offset");
    if (iter.operator++() != end) {
      uint64_t NextOffset = (*iter).first;
      InstSize = NextOffset - Offset;
    } else {
      // The instruction at Offset is the last instriuction in the input stream
      assert(Offset < FuncEnd &&
             "Attempt to find MCInst at offset beyond function end");
      InstSize = FuncEnd - Offset;
    }
    return InstSize;
  }

  uint64_t getMCInstIndex(const MachineInstr &MI) {
    unsigned NumExpOps = MI.getNumExplicitOperands();
    const MachineOperand &MO = MI.getOperand(NumExpOps);
    assert(MO.isMetadata() &&
           "Unexpected non-metadata operand in branch instruction");
    const MDNode *MDN = MO.getMetadata();
    // Unwrap metadata of the instruction to get the MCInstIndex of
    // the MCInst corresponding to this MachineInstr.
    ConstantAsMetadata *CAM = dyn_cast<ConstantAsMetadata>(MDN->getOperand(0));
    assert(CAM != nullptr && "Unexpected metadata type");
    Constant *CV = CAM->getValue();
    ConstantInt *CI = dyn_cast<ConstantInt>(CV);
    assert(CI != nullptr && "Unexpected metadata constant type");
    APInt ArbPrecInt = CI->getValue();
    return ArbPrecInt.getSExtValue();
  }

private:
  // NOTE: The following data structures are implemented to record instruction
  //       targets. Separate data structures are used instead of aggregating the
  //       target information to minimize the amount of memory allocated
  //       per instruction - given the ratio of control flow instructions is
  //       not high, in general. However it is important to populate the target
  //       information during binary parse time AND is not duplicated.
  // A sequential list of source MCInsts or 32-bit data with corresponding index
  // Iteration over std::map contents is in non-descending order of keys. So,
  // the order in the map is guaranteed to be the order of instructions in the
  // insertion order i.e., code stream order.
  std::map<uint64_t, MCInstOrData> mcInstMap;
  // All targets recorded in a set to avoid duplicate entries
  std::set<uint64_t> targetIndices;
  // A map of MCInst index, mci, to MachineBasicBlock number, mbbnum. The first
  // instruction of MachineBasicBlock number mbbnum is the MachineInstr
  // representation of the MCinst at the index, mci
  std::map<uint64_t, uint64_t> mcInstToMBBNum;

  std::map<uint64_t, std::vector<uint64_t>> MBBNumToMCInstTargetsMap;
  MachineInstr *RaiseMCInst(const MCInstrInfo &, MachineFunction &, MCInst,
                            uint64_t);
  // Start and End offsets of the array of MCInsts in mcInstVector;
  uint64_t FuncStart;
  uint64_t FuncEnd;
  // Flag to indicate that the mcInstVector includes data (or uint32_ sized
  // quantities that the disassembler was unable to recognize as instrictions
  // and are considered data
  bool dataInCode;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H
