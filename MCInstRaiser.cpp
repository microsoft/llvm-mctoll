//===-- MCInstRaiser.cpp ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCInstRaiser.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "mctoll"

void MCInstRaiser::buildCFG(MachineFunction &MF, const MCInstrAnalysis *MIA,
                            const MCInstrInfo *MII) {
  // Set the first instruction index as the entry of current MBB
  // Walk the mcInstMap
  //     a) if the current instruction is a target instruction
  //             record the (entry, current MBB) pair
  //             create a new MBB
  //             set current instruction index as entry of current MBB
  //     b) add raised MachineInstr to current MBB.
  auto targetIndicesEnd = targetIndices.end();
  uint64_t curMBBEntryInstIndex;

  for (auto mcInstorDataIter = mcInstMap.begin();
       mcInstorDataIter != mcInstMap.end(); mcInstorDataIter++) {
    uint64_t mcInstIndex = mcInstorDataIter->first;
    MCInstOrData mcInstorData = mcInstorDataIter->second;

    // If the current mcInst is a target of some instruction,
    // i) record the target of previous instruction and fall-through as
    //    needed.
    // ii) start a new MachineBasicBlock
    if (targetIndices.find(mcInstIndex) != targetIndicesEnd) {
      // Create a map of curMBBEntryInstIndex to the current
      // MachineBasicBlock for use later to create control flow edges
      // - except when creating the first MBB.
      if (MF.size()) {
        // Find the target MCInst indices of the previous MCInst
        uint64_t prevMCInstIndex = std::prev(mcInstorDataIter)->first;
        MCInstOrData prevTextSecBytes = std::prev(mcInstorDataIter)->second;
        std::vector<uint64_t> prevMCInstTargets;

        // If handling a mcInst
        if (mcInstorData.isMCInst()) {
          MCInst mcInst = mcInstorData.getMCInst();
          // If this instruction is preceeded by mcInst
          if (prevTextSecBytes.isMCInst()) {
            MCInst prevMCInst = prevTextSecBytes.getMCInst();
            // If previous MCInst is a branch
            if (MIA->isBranch(prevMCInst)) {
              uint64_t Target;
              // Get its target
              if (MIA->evaluateBranch(prevMCInst, prevMCInstIndex,
                                      (mcInstIndex - prevMCInstIndex),
                                      Target)) {
                // Record its target if it is within the function start
                // and function end.  Branch instructions with such
                // targets are - for now - treated not to be instructions
                // but most likely data bytes embedded in instruction stream.
                // TODO: How to handle any branches out of these bounds?
                // Does such a situation exist?
                if ((Target >= FuncStart) && (Target < FuncEnd)) {
                  prevMCInstTargets.push_back(Target);
                  // If previous instruction is a conditional branch, the
                  // next instruction is also a target
                  if (MIA->isConditionalBranch(prevMCInst)) {
                    if ((mcInstIndex >= FuncStart) &&
                        (mcInstIndex <= FuncEnd)) {
                      prevMCInstTargets.push_back(mcInstIndex);
                    }
                  }
                }
              }
            }
            // Previous MCInst is not a branch. So, current instruction is a
            // target
            else if ((mcInstIndex >= FuncStart) && (mcInstIndex <= FuncEnd))
              prevMCInstTargets.push_back(mcInstIndex);

            // Add to MBB -> targets map
            MBBNumToMCInstTargetsMap.insert(
                std::make_pair(MF.back().getNumber(), prevMCInstTargets));
            mcInstToMBBNum.insert(
                std::make_pair(curMBBEntryInstIndex, MF.back().getNumber()));
          } else {
            // This is preceded by data. Note that this mcInst is a target.
            // So need to start a new basic block
            // Add to MBB -> targets map
            MBBNumToMCInstTargetsMap.insert(
                std::make_pair(MF.back().getNumber(), prevMCInstTargets));
            mcInstToMBBNum.insert(
                std::make_pair(curMBBEntryInstIndex, MF.back().getNumber()));
          }
        }
      }

      // Add the new MBB to MachineFunction
      if (mcInstorData.isMCInst()) {
        MF.push_back(MF.CreateMachineBasicBlock());
        curMBBEntryInstIndex = mcInstIndex;
      }
    }
    if (mcInstorData.isMCInst()) {
      // Add raised MachineInstr to current MBB.
      MF.back().push_back(
          RaiseMCInst(*MII, MF, mcInstorData.getMCInst(), mcInstIndex));
    }
  }

  // Add the entry instruction -> MBB map entry for the last MBB
  if (MF.size()) {
    MBBNumToMCInstTargetsMap.insert(
        std::make_pair(MF.back().getNumber(), std::vector<uint64_t>()));
    mcInstToMBBNum.insert(
        std::make_pair(curMBBEntryInstIndex, MF.back().getNumber()));
  }

  // Walk all MachineBasicBlocks in MF to add control flow edges
  unsigned mbbCount = MF.getNumBlockIDs();
  for (unsigned mbbIndex = 0; mbbIndex < mbbCount; mbbIndex++) {
    // Get the MBB
    MachineBasicBlock *currentMBB = MF.getBlockNumbered(mbbIndex);
    std::map<uint64_t, std::vector<uint64_t>>::iterator iter =
        MBBNumToMCInstTargetsMap.find(mbbIndex);
    assert(iter != MBBNumToMCInstTargetsMap.end());
    std::vector<uint64_t> targetMCInstIndices = iter->second;
    for (auto mbbMCInstTgt : targetMCInstIndices) {
      std::map<uint64_t, uint64_t>::iterator tgtIter =
          mcInstToMBBNum.find(mbbMCInstTgt);
      // If the target is not found, it could be outside the function
      // being constructed.
      // TODO: Need to keep track of all such targets and link them in
      // a later global pass over all MachineFunctions of the module.
      if (tgtIter == mcInstToMBBNum.end()) {
        outs() << "**** Warning : Index ";
        outs().write_hex(mbbMCInstTgt);
        outs() << " not found\n";
      } else if (!MF.getBlockNumbered(mbbIndex)->isReturnBlock()) {
        MachineBasicBlock *succ = MF.getBlockNumbered(tgtIter->second);
        currentMBB->addSuccessorWithoutProb(succ);
      }
    }
  }

  // Print the Machine function (which contains the reconstructed
  // MachineBasicBlocks.
  LLVM_DEBUG(dbgs() << "Generated CFG\n");
  LLVM_DEBUG(MF.dump());
}

static inline int64_t raiseSignedImm(int64_t val, const DataLayout &dl) {
  if (dl.getPointerSize() == 4)
    return static_cast<int32_t>(val);

  return val;
}

MachineInstr *MCInstRaiser::RaiseMCInst(const MCInstrInfo &mcInstrInfo,
                                        MachineFunction &machineFunction,
                                        MCInst mcInst, uint64_t mcInstIndex) {
  // Construct MachineInstr that is the raised abstraction of MCInstr
  const MCInstrDesc &mcInstrDesc = mcInstrInfo.get(mcInst.getOpcode());
  DebugLoc *debugLoc = new DebugLoc();
  MachineInstrBuilder builder =
      BuildMI(machineFunction, *debugLoc, mcInstrDesc);

  // Get the number of declared MachineOperands for this
  // MachineInstruction and add them to the MachineInstr being
  // constructed. Any implicitDefs or implicitDefs would already have
  // been added while MachineInstr is created during the construction
  // of builder object above.
  const unsigned int defCount = mcInstrDesc.getNumDefs();
  const unsigned int numOperands = mcInstrDesc.getNumOperands();
  for (unsigned int indx = 0; indx < numOperands; indx++) {
    // Raise operand
    MCOperand mcOperand = mcInst.getOperand(indx);
    if (mcOperand.isImm()) {
      builder.addImm(
          raiseSignedImm(mcOperand.getImm(), machineFunction.getDataLayout()));
    } else if (mcOperand.isReg()) {
      // The first defCount operands are defines (i.e., out operands).
      if (indx < defCount)
        builder.addDef(mcOperand.getReg());
      else
        builder.addUse(mcOperand.getReg());
    } else {
      outs() << "**** Unhandled Operand : ";
      LLVM_DEBUG(mcOperand.dump());
    }
  }

  LLVMContext &C = machineFunction.getFunction().getContext();
  // Creation of MDNode representing Metadata with mcInstIndex may be done using
  // the following couple of lines of code. But I just wanted to spell it out
  // for better understanding.

  // MDNode* temp_N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C,
  //                                                  llvm::APInt(64,
  //                                                              mcInstIndex,
  //                                                              false))));
  // MDNode* N = MDNode::get(C, temp_N);

  // Create arbitrary precision
  // integer
  llvm::APInt ArbPrecInt(64, mcInstIndex, false);
  // Create ConstantAsMetadata
  ConstantAsMetadata *CMD =
      ConstantAsMetadata::get(ConstantInt::get(C, ArbPrecInt));
  MDNode *N = MDNode::get(C, CMD);
  builder.addMetadata(N);
  return builder.getInstr();
}

void MCInstRaiser::dump() const {
  for (auto in : mcInstMap) {
    uint64_t mcInstIndex = in.first;
    MCInstOrData mcInstorData = in.second;
    LLVM_DEBUG(dbgs() << "0x" << format("%016" PRIx64, mcInstIndex) << ": ");
    LLVM_DEBUG(mcInstorData.dump());
  }
}

bool MCInstRaiser::adjustFuncEnd(uint64_t n) {
  // NOTE: At present it appears that we only need it to increase the function
  // end index.
  if (FuncEnd > n)
    return false;

  FuncEnd = n;
  return true;
}

void MCInstRaiser::addMCInstOrData(uint64_t index, MCInstOrData mcInst) {
  // Set dataInCode flag as appropriate
  if (mcInst.isData() && !dataInCode)
    dataInCode = true;

  mcInstMap.insert(std::make_pair(index, mcInst));
}

int64_t MCInstRaiser::getMBBNumberOfMCInstOffset(uint64_t Offset,
                                                 MachineFunction &MF) const {
  if ((Offset < FuncStart) || (Offset > FuncEnd))
    return -1;
  auto iter = mcInstToMBBNum.find(Offset);
  if (iter != mcInstToMBBNum.end())
    return (*iter).second;

  // MBBNo not found. Check to see if the Offset corresponds to a non-leading
  // instruction of any of the blocks. Such a situation may occur when this
  // function is called before noops are deleted.
  for (auto N : mcInstToMBBNum) {
    uint64_t CurMBBStartOffset = N.first;
    uint64_t CurMBBNo = N.second;
    auto CurMBB = MF.getBlockNumbered(CurMBBNo);
    unsigned CurMBBSizeinBytes = 0;
    for (const MachineInstr &I : CurMBB->instrs()) {
      CurMBBSizeinBytes += getMCInstSize(getMCInstIndex(I));
    }
    if ((CurMBBStartOffset <= Offset) &&
        (Offset < CurMBBStartOffset + CurMBBSizeinBytes)) {
      return CurMBBNo;
    }
  }
  return -1;
}

int64_t MCInstRaiser::getMCInstOffsetOfMBBNumber(uint64_t MBBNum) const {
  auto iter =
      std::find_if(mcInstToMBBNum.begin(), mcInstToMBBNum.end(),
                   [MBBNum](auto &&item) { return item.second == MBBNum; });

  if (iter != mcInstToMBBNum.end())
    return iter->first;
  return -1;
}

uint64_t MCInstRaiser::getMCInstSize(uint64_t Offset) const {
  const_mcinst_iter Iter = mcInstMap.find(Offset);
  const_mcinst_iter End = mcInstMap.end();
  assert(Iter != End && "Attempt to find MCInst at non-existent offset");

  if (Iter.operator++() != End) {
    uint64_t NextOffset = (*Iter).first;
    return NextOffset - Offset;
  }

  // The instruction at Offset is the last instriuction in the input stream
  assert(Offset < FuncEnd &&
         "Attempt to find MCInst at offset beyond function end");
  return FuncEnd - Offset;
}

uint64_t MCInstRaiser::getMCInstIndex(const MachineInstr &MI) const {
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

#undef DEBUG_TYPE
