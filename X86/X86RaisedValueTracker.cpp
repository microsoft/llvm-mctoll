//==-- X86MachineInstructionRaiser.h - Binary raiser utility llvm-mctoll =====//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of X86RaisedValueTracker
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "X86RaisedValueTracker.h"
#include "X86RaiserUtils.h"

X86RaisedValueTracker::X86RaisedValueTracker(
    X86MachineInstructionRaiser *MIRaiser) {
  x86MIRaiser = MIRaiser;
  // Initialize entries for function register arguments in physToValueMap
  // Only first 6 arguments are passed as registers
  unsigned RegArgCount = GPR64ArgRegs64Bit.size();
  MachineFunction &MF = x86MIRaiser->getMF();
  Function *CurFunction = x86MIRaiser->getRaisedFunction();

  for (auto &Arg : CurFunction->args()) {
    unsigned ArgNum = Arg.getArgNo();
    if (ArgNum > RegArgCount)
      break;
    Type *ArgTy = Arg.getType();
    // TODO : Handle non-integer argument types
    assert(ArgTy->isIntegerTy() &&
           "Unhandled argument type in raised function type");
    unsigned ArgTySzInBits = ArgTy->getPrimitiveSizeInBits();
    physRegDefsInMBB[GPR64ArgRegs64Bit[ArgNum]][0] =
        std::make_pair(ArgTySzInBits, nullptr);
  }
  // Walk all blocks to initialize physRegDefsInMBB based on register defs.
  for (MachineBasicBlock &MBB : MF) {
    int MBBNo = MBB.getNumber();
    // Walk MachineInsts of the MachineBasicBlock
    for (MachineBasicBlock::iterator mbbIter = MBB.instr_begin(),
                                     mbbEnd = MBB.instr_end();
         mbbIter != mbbEnd; mbbIter++) {
      MachineInstr &MI = *mbbIter;
      // Look at all defs - explicit and implicit.
      unsigned NumDefs = MI.getNumDefs();

      for (unsigned i = 0, e = MI.getNumOperands(); NumDefs && i != e; ++i) {
        MachineOperand &MO = MI.getOperand(i);
        if (!MO.isReg() || !MO.isDef())
          continue;

        unsigned int PhysReg = MO.getReg();
        if ((PhysReg == X86::FPSW) || (PhysReg == X86::FPCW))
          continue;

        unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);
        // No value assigned yet for the definition of SuperReg in CurMBBNo.
        // The value will be updated as the block is raised.
        uint8_t PhysRegSzInBits = 0;
        if (is64BitPhysReg(PhysReg))
          PhysRegSzInBits = 64;
        else if (is32BitPhysReg(PhysReg) || (PhysReg == X86::EFLAGS))
          PhysRegSzInBits = 32;
        else if (is16BitPhysReg(PhysReg))
          PhysRegSzInBits = 16;
        else if (is8BitPhysReg(PhysReg))
          PhysRegSzInBits = 8;
        else
          assert(false && "Unexpected Physical register encountered");

        physRegDefsInMBB[SuperReg][MBBNo] =
            std::make_pair(PhysRegSzInBits, nullptr);
      }
    }
  }
}

// Record Val as the most recent definition of PhysReg in BasicBlock
// corresponding to MachinebasicBlock with number MBBNo. This is nothing but
// local value numbering (i.e., value numbering within the block
// corresponding to MBBNo.
bool X86RaisedValueTracker::updatePhysRegSSAValue(unsigned int PhysReg,
                                                  int MBBNo, Value *Val) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);
  physRegDefsInMBB[SuperReg][MBBNo].second = Val;
  return true;
}

// Find the defined value of SuperReg in MBBNo. Return the reaching definition
// <MBBNo, Value> pair of SuperReg into MBBNo. If the basic block with number
// MBBNo does not define SuperReg, return <MBBNo, nullptr>. Note that this
// function does NOT walk the predecessors of MBBNo to find reaching definition
// of SuperReg.

std::pair<int, Value *>
X86RaisedValueTracker::getInBlockReachingDef(unsigned int PhysReg, int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);

  // TODO : Support outside of GPRs need to be implemented.
  // Find the per-block definitions SuperReg
  PhysRegMBBValueDefMap::iterator PhysRegBBValDefIter =
      physRegDefsInMBB.find(SuperReg);
  // If per-block definition map exists
  if (PhysRegBBValDefIter != physRegDefsInMBB.end()) {
    // Find if there is a definition in MBB with number MBBNo
    MBBNoToValueMap mbbToValMap = PhysRegBBValDefIter->second;
    MBBNoToValueMap::iterator mbbToValMapIter = mbbToValMap.find(MBBNo);
    if (mbbToValMapIter != mbbToValMap.end()) {
      return std::make_pair(mbbToValMapIter->first,
                            mbbToValMapIter->second.second);
    }
  }
  // MachineBasicBlock with MBBNo does not define SuperReg.
  // MBB number should be ignored when Value ie nullptr
  return std::make_pair(MBBNo, nullptr);
}

// This function looks for reaching definitions of PhysReg from all the
// predecessors of block MBBNo by walking its predecessors. Returns a vector of
// reaching definitions only if there is a reaching definition along all the
// predecessors.

std::vector<std::pair<int, Value *>>
X86RaisedValueTracker::getGlobalReachingDefs(unsigned int PhysReg, int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);
  std::vector<std::pair<int, Value *>> ReachingDefs;
  // Recursively walk the predecessors of current block to get
  // the reaching definition for PhysReg.

  MachineFunction &MF = x86MIRaiser->getMF();
  MachineBasicBlock *CurMBB = MF.getBlockNumbered(MBBNo);

  // For each of the predecessors find if SuperReg has a definition in its
  // reach tree.
  for (auto P : CurMBB->predecessors()) {
    SmallVector<MachineBasicBlock *, 8> WorkList;
    // No blocks visited in this walk up the predecessor P
    BitVector BlockVisited(MF.getNumBlockIDs(), false);

    // Start at predecessor P
    WorkList.push_back(P);

    while (!WorkList.empty()) {
      MachineBasicBlock *PredMBB = WorkList.pop_back_val();
      if (!BlockVisited[PredMBB->getNumber()]) {
        // Mark block as visited
        BlockVisited.set(PredMBB->getNumber());
        const std::pair<int, Value *> ReachInfo =
            getInBlockReachingDef(SuperReg, PredMBB->getNumber());

        // if reach info found, record it
        if (ReachInfo.second != nullptr)
          ReachingDefs.push_back(ReachInfo);
        else {
          // Reach info not found, continue walking the predecessors of CurBB.
          for (auto P : PredMBB->predecessors()) {
            // push_back the block which was not visited.
            if (!BlockVisited[P->getNumber()])
              WorkList.push_back(P);
          }
        }
      }
    }
  }

  // Clean up any duplicate entries in ReachingDefs
  if (ReachingDefs.size() > 1) {
    // Should have found a reaching definition on each of the predecessor edges
    assert(ReachingDefs.size() == CurMBB->pred_size() &&
           "Inconsistent number of reaching definitions found");

    std::sort(ReachingDefs.begin(), ReachingDefs.end());
    auto LastElem = std::unique(ReachingDefs.begin(), ReachingDefs.end());
    ReachingDefs.erase(LastElem, ReachingDefs.end());
  }

  return ReachingDefs;
}

// Get last defined value of PhysReg in MBBNo. Returns nullptr if no definition
// is found. NOTE: If this function is called while raising MBBNo, this returns
// a value representing most recent definition of PhysReg as of current
// translation state. If this function is called after raising MBBNo, this
// returns a value representing the last definition of PhysReg in the block.

Value *X86RaisedValueTracker::getInBlockPhysRegDefVal(unsigned int PhysReg,
                                                      int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);

  // TODO : Support outside of GPRs need to be implemented.
  // Find the per-block definitions SuperReg
  PhysRegMBBValueDefMap::iterator PhysRegBBValDefIter =
      physRegDefsInMBB.find(SuperReg);
  // If per-block definition map exists
  if (PhysRegBBValDefIter != physRegDefsInMBB.end()) {
    // Find if there is a definition in MBB with number MBBNo
    MBBNoToValueMap mbbToValMap = PhysRegBBValDefIter->second;
    MBBNoToValueMap::iterator mbbToValMapIter = mbbToValMap.find(MBBNo);
    if (mbbToValMapIter != mbbToValMap.end()) {
      return mbbToValMapIter->second.second;
    }
  }
  // MachineBasicBlock with MBBNo does not define SuperReg.
  return nullptr;
}

// Get size of PhysReg last defined in MBBNo.
// NOTE: If this function is called while raising MBBNo, this returns a size
// of PhysReg most recently defined during the translation of the block numbered
// MBBNo. If this function is called after raising MBBNo, this returns the size
// of PhysReg last defined in MBBNo.

unsigned X86RaisedValueTracker::getInBlockPhysRegSize(unsigned int PhysReg,
                                                      int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);

  // TODO : Support outside of GPRs need to be implemented.
  // Find the per-block definitions SuperReg
  PhysRegMBBValueDefMap::iterator PhysRegBBValDefIter =
      physRegDefsInMBB.find(SuperReg);
  // If per-block definition map exists
  if (PhysRegBBValDefIter != physRegDefsInMBB.end()) {
    // Find if there is a definition in MBB with number MBBNo
    MBBNoToValueMap mbbToValMap = PhysRegBBValDefIter->second;
    MBBNoToValueMap::iterator mbbToValMapIter = mbbToValMap.find(MBBNo);
    if (mbbToValMapIter != mbbToValMap.end()) {
      return mbbToValMapIter->second.first;
    }
  }
  // MachineBasicBlock with MBBNo does not define SuperReg.
  return 0;
}

// Get the reaching definition of PhysReg. This function looks for
// reaching definition in block MBBNo. If not found, walks its predecessors
// to find all reaching definitions. If the reaching definitions are different
// the register is promoted to a stack slot. In other words, a stack slot is
// created, all the reaching definitions are stored in the basic blocks that
// define them. In the current basic block, use of this register is raised
// as load from the the stack slot.
Value *X86RaisedValueTracker::getReachingDef(unsigned int PhysReg, int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);
  Value *RetValue = nullptr;

  std::vector<std::pair<int, Value *>> ReachingDefs;
  // Look for the most recent definition of SuperReg in current block.
  const std::pair<int, Value *> LocalDef =
      getInBlockReachingDef(SuperReg, MBBNo);

  if (LocalDef.second != nullptr) {
    assert((LocalDef.first == MBBNo) && "Inconsistent local def info found");
    RetValue = LocalDef.second;
  } else {
    MachineFunction &MF = x86MIRaiser->getMF();
    const ModuleRaiser *MR = x86MIRaiser->getModuleRaiser();
    ReachingDefs = getGlobalReachingDefs(PhysReg, MBBNo);
    // If there are more than one distinct incoming reaching defs
    if (ReachingDefs.size() > 1) {
      // 1. Allocate 64-bit stack slot
      // 2. store each of the incoming values in that stack slot. cast the value
      // as needed.
      // 3. load from the stack slot
      // 4. Return loaded value - RetValue

      // 1. Allocate 64-bit stack slot
      LLVMContext &Ctxt(MF.getFunction().getContext());
      const DataLayout &DL = MR->getModule()->getDataLayout();
      unsigned allocaAddrSpace = DL.getAllocaAddrSpace();
      Type *AllocTy = Type::getInt64Ty(Ctxt);
      unsigned int typeAlignment = DL.getPrefTypeAlignment(AllocTy);
      ;

      // Create alloca instruction to allocate stack slot
      AllocaInst *Alloca =
          new AllocaInst(AllocTy, allocaAddrSpace, 0, typeAlignment, "");

      // Create a stack slot associated with the alloca instruction of size 8
      unsigned int StackFrameIndex = MF.getFrameInfo().CreateStackObject(
          typeAlignment, DL.getPrefTypeAlignment(AllocTy),
          false /* isSpillSlot */, Alloca);

      // Compute size of new stack object.
      const MachineFrameInfo &MFI = MF.getFrameInfo();
      // Size of currently allocated object size
      int64_t ObjectSize = MFI.getObjectSize(StackFrameIndex);
      // Size of object at previous index; 0 if this is the first object on
      // stack.
      int64_t PrevObjectSize =
          (StackFrameIndex != 0) ? MFI.getObjectOffset(StackFrameIndex - 1) : 0;
      int64_t Offset = PrevObjectSize - ObjectSize;

      // Set object size.
      MF.getFrameInfo().setObjectOffset(StackFrameIndex, Offset);

      // Add the alloca instruction to entry block
      x86MIRaiser->insertAllocaInEntryBlock(Alloca);

      // If PhysReg is defined in MBBNo, store the defined value in the
      // newly created stack slot.
      std::pair<int, Value *> MBBNoRDPair =
          getInBlockReachingDef(PhysReg, MBBNo);
      Value *DefValue = MBBNoRDPair.second;
      assert(MBBNoRDPair.first == MBBNo &&
             "Unexpected result of in-block reaching value lookup");
      if (MBBNoRDPair.second != nullptr) {
        StoreInst *StInst = new StoreInst(DefValue, Alloca);
        x86MIRaiser->getRaisedFunction()
            ->getEntryBlock()
            .getInstList()
            .push_back(StInst);
      }
      // The store instruction simply stores value defined on stack. No defines
      // are affected. So, no PhysReg to SSA mapping needs to be updated.

      // 2. Store each of the reaching definitions at the end of corresponding
      // blocks that define them in that stack slot. Cast the value as needed.
      for (auto const &MBBVal : ReachingDefs) {
        // Find the BasicBlock corresponding to MachineBasicBlock in MBBVal
        // map.
        if (MBBVal.second == nullptr) {
          // This is an incoming edge from a block that is not yet
          // raised. Record this in the set of incomplete promotions that will
          // be handled after all blocks are raised.
          x86MIRaiser->recordDefsToPromote(SuperReg, MBBVal.first, Alloca);
        } else {
          StoreInst *StInst = x86MIRaiser->promotePhysregToStackSlot(
              SuperReg, MBBVal.second, MBBVal.first, Alloca);
          assert(StInst != nullptr &&
                 "Failed to promote reaching definition to stack slot");
        }
      }
      // 3. load from the stack slot for use in current block
      LoadInst *LdReachingVal = new LoadInst(Alloca);
      // Insert load instruction
      x86MIRaiser->getRaisedBasicBlock(MF.getBlockNumbered(MBBNo))
          ->getInstList()
          .push_back(LdReachingVal);
      RetValue = LdReachingVal;
      // Record that PhysReg is now defined as load from stack location in
      // current MBB with MBBNo.
      updatePhysRegSSAValue(PhysReg, MBBNo, RetValue);
    } else if (ReachingDefs.size() == 1)
      // Just return the value of the single reaching definition
      RetValue = ReachingDefs[0].second;
  }
  return RetValue;
}
