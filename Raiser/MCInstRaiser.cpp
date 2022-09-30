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

using namespace llvm;
using namespace llvm::mctoll;

void MCInstRaiser::buildCFG(MachineFunction &MF, const MCInstrAnalysis *MIA,
                            const MCInstrInfo *MII) {
  // Set the first instruction index as the entry of current MBB
  // Walk the mcInstMap
  //     a) if the current instruction is a target instruction
  //             record the (entry, current MBB) pair
  //             create a new MBB
  //             set current instruction index as entry of current MBB
  //     b) add raised MachineInstr to current MBB.
  auto TargetIndicesEnd = TargetIndices.end();
  uint64_t CurMBBEntryInstIndex;

  for (auto MCInstorDataIter = InstMap.begin();
       MCInstorDataIter != InstMap.end(); MCInstorDataIter++) {
    uint64_t MCInstIndex = MCInstorDataIter->first;
    MCInstOrData MCInstorData = MCInstorDataIter->second;

    // If the current mcInst is a target of some instruction,
    // i) record the target of previous instruction and fall-through as
    //    needed.
    // ii) start a new MachineBasicBlock
    if (TargetIndices.find(MCInstIndex) != TargetIndicesEnd) {
      // Create a map of curMBBEntryInstIndex to the current
      // MachineBasicBlock for use later to create control flow edges
      // - except when creating the first MBB.
      if (MF.size()) {
        // Find the target MCInst indices of the previous MCInst
        uint64_t PrevMCInstIndex = std::prev(MCInstorDataIter)->first;
        MCInstOrData PrevTextSecBytes = std::prev(MCInstorDataIter)->second;
        std::vector<uint64_t> PrevMCInstTargets;

        // If handling a mcInst
        if (MCInstorData.isMCInst()) {
          MCInst MCInstr = MCInstorData.getMCInst();
          // If this instruction is preceeded by mcInst
          if (PrevTextSecBytes.isMCInst()) {
            MCInst PrevMCInst = PrevTextSecBytes.getMCInst();
            // If previous MCInst is a branch
            if (MIA->isBranch(PrevMCInst)) {
              uint64_t Target;
              // Get its target
              if (MIA->evaluateBranch(PrevMCInst, PrevMCInstIndex,
                                      (MCInstIndex - PrevMCInstIndex),
                                      Target)) {
                // Record its target if it is within the function start
                // and function end.  Branch instructions with such
                // targets are - for now - treated not to be instructions
                // but most likely data bytes embedded in instruction stream.
                // TODO: How to handle any branches out of these bounds?
                // Does such a situation exist?
                if ((Target >= FuncStart) && (Target < FuncEnd)) {
                  PrevMCInstTargets.push_back(Target);
                  // If previous instruction is a conditional branch, the
                  // next instruction is also a target
                  if (MIA->isConditionalBranch(PrevMCInst)) {
                    if ((MCInstIndex >= FuncStart) &&
                        (MCInstIndex <= FuncEnd)) {
                      PrevMCInstTargets.push_back(MCInstIndex);
                    }
                  }
                }
              }
            }
            // Previous MCInst is not a branch. So, current instruction is a
            // target
            else if ((MCInstIndex >= FuncStart) && (MCInstIndex <= FuncEnd))
              PrevMCInstTargets.push_back(MCInstIndex);

            // Add to MBB -> targets map
            MBBNumToMCInstTargetsMap.insert(
                std::make_pair(MF.back().getNumber(), PrevMCInstTargets));
            InstToMBBNum.insert(
                std::make_pair(CurMBBEntryInstIndex, MF.back().getNumber()));
          } else {
            // This is preceded by data. Note that this mcInst is a target.
            // So need to start a new basic block
            // Add to MBB -> targets map
            MBBNumToMCInstTargetsMap.insert(
                std::make_pair(MF.back().getNumber(), PrevMCInstTargets));
            InstToMBBNum.insert(
                std::make_pair(CurMBBEntryInstIndex, MF.back().getNumber()));
          }
        }
      }

      // Add the new MBB to MachineFunction
      if (MCInstorData.isMCInst()) {
        MF.push_back(MF.CreateMachineBasicBlock());
        CurMBBEntryInstIndex = MCInstIndex;
      }
    }
    if (MCInstorData.isMCInst()) {
      // Add raised MachineInstr to current MBB.
      MF.back().push_back(
          RaiseMCInst(*MII, MF, MCInstorData.getMCInst(), MCInstIndex));
    }
  }

  // Add the entry instruction -> MBB map entry for the last MBB
  if (MF.size()) {
    // If the terminating instruction of last MBB is a branch instruction,
    // ensure appropriate control flow edges are added.
    std::vector<uint64_t> TermMCInstTargets;
    auto MCIDMapIter = InstMap.rbegin();
    if (MCIDMapIter != InstMap.rend()) {
      uint64_t TermMCInstIndex = MCIDMapIter->first;
      auto TermMCInst = MCIDMapIter->second.getMCInst();
      // The following code handles a situation where the text section ends with
      // an unconditional branch. In such situations, no fall-through target is
      // recorded in targetIndices since offset after the branch is not within
      // the function boundary. The above loop relies on a fall-through being
      // registered to add control flow edges and we have no fall-through edge
      // to add them for the last MBB with a branch. If the function were padded
      // with noop, this would not trigger and the case would be naturally
      // handled in the above loop.
      if (MIA->isBranch(TermMCInst)) {
        uint64_t Target;
        // Get its target
        assert(!MIA->isConditionalBranch(TermMCInst) &&
               "Unexpected conditional branch at the end of text section");
        // Since this instruction is the last one, its size is
        // (FuncEnd - termMCInstIndex).
        if (MIA->evaluateBranch(TermMCInst, TermMCInstIndex,
                                (FuncEnd - TermMCInstIndex), Target)) {
          // Record its target if it is within the function start
          // and function end.  Branch instructions with such
          // targets are - for now - treated not to be instructions
          // but most likely data bytes embedded in instruction stream.
          // TODO: How to handle any branches out of these bounds?
          // Does such a situation exist?
          if ((Target >= FuncStart) && (Target < FuncEnd)) {
            TermMCInstTargets.push_back(Target);
          }
        }
      }
    }
    MBBNumToMCInstTargetsMap.insert(
        std::make_pair(MF.back().getNumber(), TermMCInstTargets));
    InstToMBBNum.insert(
        std::make_pair(CurMBBEntryInstIndex, MF.back().getNumber()));
  }

  // Walk all MachineBasicBlocks in MF to add control flow edges
  unsigned MBBCount = MF.getNumBlockIDs();
  for (unsigned MBBIndex = 0; MBBIndex < MBBCount; MBBIndex++) {
    // Get the MBB
    MachineBasicBlock *CurrentMBB = MF.getBlockNumbered(MBBIndex);
    std::map<uint64_t, std::vector<uint64_t>>::iterator Iter =
        MBBNumToMCInstTargetsMap.find(MBBIndex);
    assert(Iter != MBBNumToMCInstTargetsMap.end());
    std::vector<uint64_t> TargetMCInstIndices = Iter->second;
    for (auto MBBMCInstTgt : TargetMCInstIndices) {
      std::map<uint64_t, uint64_t>::iterator TgtIter =
          InstToMBBNum.find(MBBMCInstTgt);
      // If the target is not found, it could be outside the function
      // being constructed.
      // TODO: Need to keep track of all such targets and link them in
      // a later global pass over all MachineFunctions of the module.
      if (TgtIter == InstToMBBNum.end()) {
        outs() << "**** Warning : Index ";
        outs().write_hex(MBBMCInstTgt);
        outs() << " not found\n";
      } else if (!MF.getBlockNumbered(MBBIndex)->isReturnBlock()) {
        MachineBasicBlock *Succ = MF.getBlockNumbered(TgtIter->second);
        CurrentMBB->addSuccessorWithoutProb(Succ);
      }
    }
  }

  // Print the Machine function (which contains the reconstructed
  // MachineBasicBlocks.
  LLVM_DEBUG(dbgs() << "Generated CFG\n");
  LLVM_DEBUG(MF.dump());
}

static inline int64_t raiseSignedImm(int64_t Val, const DataLayout &DL) {
  if (DL.getPointerSize() == 4)
    return static_cast<int32_t>(Val);

  return Val;
}

MachineInstr *MCInstRaiser::RaiseMCInst(const MCInstrInfo &InstrInfo,
                                        MachineFunction &MF,
                                        MCInst Inst, uint64_t InstIndex) {
  // Construct MachineInstr that is the raised abstraction of MCInstr
  const MCInstrDesc &InstrDesc = InstrInfo.get(Inst.getOpcode());
  DebugLoc *DL = new DebugLoc();
  MachineInstrBuilder Builder =
      BuildMI(MF, *DL, InstrDesc);

  // Get the number of declared MachineOperands for this
  // MachineInstruction and add them to the MachineInstr being
  // constructed. Any implicitDefs or implicitDefs would already have
  // been added while MachineInstr is created during the construction
  // of builder object above.
  const unsigned int DefCount = InstrDesc.getNumDefs();
  const unsigned int NumOperands = InstrDesc.getNumOperands();
  for (unsigned int Indx = 0; Indx < NumOperands; Indx++) {
    // Raise operand
    MCOperand Operand = Inst.getOperand(Indx);
    if (Operand.isImm()) {
      Builder.addImm(
          raiseSignedImm(Operand.getImm(), MF.getDataLayout()));
    } else if (Operand.isReg()) {
      // The first defCount operands are defines (i.e., out operands).
      if (Indx < DefCount)
        Builder.addDef(Operand.getReg());
      else
        Builder.addUse(Operand.getReg());
    } else {
      outs() << "**** Unhandled Operand : ";
      LLVM_DEBUG(Operand.dump());
    }
  }

  LLVMContext &C = MF.getFunction().getContext();
  // Creation of MDNode representing Metadata with mcInstIndex may be done
  // using the following couple of lines of code. But I just wanted to spell
  // it out for better understanding.

  // MDNode* temp_N = MDNode::get(C,
  // ConstantAsMetadata::get(ConstantInt::get(C,
  //                                                  llvm::APInt(64,
  //                                                              mcInstIndex,
  //                                                              false))));
  // MDNode* N = MDNode::get(C, temp_N);

  // Create arbitrary precision
  // integer
  llvm::APInt ArbPrecInt(64, InstIndex, false);
  // Create ConstantAsMetadata
  ConstantAsMetadata *CMD =
      ConstantAsMetadata::get(ConstantInt::get(C, ArbPrecInt));
  MDNode *N = MDNode::get(C, CMD);
  Builder.addMetadata(N);
  return Builder.getInstr();
}

void MCInstRaiser::dump(const MCInstPrinter *Printer,
                        StringRef Separator,
                        const MCRegisterInfo *RegInfo) const {
  for (auto In : InstMap) {
    uint64_t InstIndex = In.first;
    MCInstOrData InstorData = In.second;
    LLVM_DEBUG(dbgs() << "0x" << format("%016" PRIx64, InstIndex) << ": ");
    LLVM_DEBUG(InstorData.dump(Printer, Separator, RegInfo));
  }
}

bool MCInstRaiser::adjustFuncEnd(uint64_t N) {
  // NOTE: At present it appears that we only need it to increase the function
  // end index.
  if (FuncEnd > N)
    return false;

  FuncEnd = N;
  return true;
}

void MCInstRaiser::addMCInstOrData(uint64_t Index, MCInstOrData Inst) {
  // Set dataInCode flag as appropriate
  if (Inst.isData() && !DataInCode)
    DataInCode = true;

  InstMap.insert(std::make_pair(Index, Inst));
}

int64_t MCInstRaiser::getMBBNumberOfMCInstOffset(uint64_t Offset,
                                                 MachineFunction &MF) const {
  if ((Offset < FuncStart) || (Offset > FuncEnd))
    return -1;
  auto Iter = InstToMBBNum.find(Offset);
  if (Iter != InstToMBBNum.end())
    return (*Iter).second;

  // MBBNo not found. Check to see if the Offset corresponds to a non-leading
  // instruction of any of the blocks. Such a situation may occur when this
  // function is called before noops are deleted.
  for (auto N : InstToMBBNum) {
    uint64_t CurMBBStartOffset = N.first;
    uint64_t CurMBBNo = N.second;
    auto *CurMBB = MF.getBlockNumbered(CurMBBNo);
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
  auto Iter =
      std::find_if(InstToMBBNum.begin(), InstToMBBNum.end(),
                   [MBBNum](auto &&Item) { return Item.second == MBBNum; });

  if (Iter != InstToMBBNum.end())
    return Iter->first;
  return -1;
}

uint64_t MCInstRaiser::getMCInstSize(uint64_t Offset) const {
  const_mcinst_iter Iter = InstMap.find(Offset);
  const_mcinst_iter End = InstMap.end();
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
  const MachineOperand &MO = NumExpOps < MI.getNumOperands()
                                 ? MI.getOperand(NumExpOps)
                                 : MI.getOperand(MI.getNumOperands() - 1);
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
