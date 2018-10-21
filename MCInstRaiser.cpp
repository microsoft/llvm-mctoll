//===-- MCInstRaiser.cpp - Binary raiser utility llvm-mctoll --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of MCInstrRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "MCInstRaiser.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Support/raw_ostream.h"

void MCInstRaiser::buildCFG(MachineFunction &MF, const MCInstrAnalysis *MIA,
                            const MCInstrInfo *MII) {
  bool PrintAll =
      (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() > 0);
  if (PrintAll)
    outs() << "Running buildCFG\n";

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
        if (mcInstorData.is_mcInst()) {
          MCInst mcInst = mcInstorData.get_mcInst();
          // If this instruction is preceeded by mcInst
          if (prevTextSecBytes.is_mcInst()) {
            MCInst prevMCInst = prevTextSecBytes.get_mcInst();
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
                if ((Target >= FuncStart) && (Target <= FuncEnd)) {
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
            else if ((mcInstIndex >= FuncStart) && (mcInstIndex <= FuncEnd)) {
              prevMCInstTargets.push_back(mcInstIndex);
            }

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
      if (mcInstorData.is_mcInst()) {
        MF.push_back(MF.CreateMachineBasicBlock());
        curMBBEntryInstIndex = mcInstIndex;
      }
    }

    if (mcInstorData.is_mcInst()) {
      // add raised MachineInstr to current MBB.
      MF.back().push_back(
          RaiseMCInst(*MII, MF, mcInstorData.get_mcInst(), mcInstIndex));
    }
  }

  // Add the entry intruction -> MBB map entry for the last MBB
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
        // assert(0);
      } else {
        MachineBasicBlock *succ = MF.getBlockNumbered(tgtIter->second);
        currentMBB->addSuccessorWithoutProb(succ);
      }
    }
  }

  // Print the Machine function (which contains the reconstructed
  // MachineBasicBlocks.
  if (PrintAll)
    MF.dump();
}

static inline int64_t raiseSignedImm(int64_t val, const DataLayout &dl) {
  if (dl.getPointerSize() == 4)
    return static_cast<int32_t>(val);
  else 
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
      mcOperand.dump();
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
  // MDNode* temp_N = MDNode::get(C, CMD);
  MDNode *N = MDNode::get(C, CMD);
  builder.addMetadata(N);
  return builder.getInstr();
}

void MCInstRaiser::dump() const {
  for (auto in : mcInstMap) {
    outs() << in.first << " : ";
    in.second.dump();
  }
}

bool MCInstRaiser::adjustFuncEnd(uint64_t n) {
  // NOTE: At present it appears that we only need it to increase the function
  // end index.
  if (FuncEnd > n) {
    return false;
  }
  FuncEnd = n;
  return true;
}

void MCInstRaiser::addMCInstOrData(uint64_t index, MCInstOrData mcInst) {
  // Set dataInCode flag as appropriate
  if (mcInst.is_data() && !dataInCode) {
    dataInCode = true;
  }
  mcInstMap.insert(std::make_pair(index, mcInst));
}
