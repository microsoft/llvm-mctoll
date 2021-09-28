//===-- X86RaisedValueTracker.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of X86RaisedValueTracker
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "X86RaisedValueTracker.h"
#include "InstMetadata.h"
#include "RuntimeFunction.h"
#include "X86RegisterUtils.h"
#include "llvm/Support/Debug.h"
#include <X86InstrBuilder.h>
#include <X86Subtarget.h>

#define DEBUG_TYPE "mctoll"

using namespace X86RegisterUtils;
using namespace mctoll;

X86RaisedValueTracker::X86RaisedValueTracker(
    X86MachineInstructionRaiser *MIRaiser)
    : x86MIRaiser(MIRaiser) {

  // Initialize entries for function register arguments in physToValueMap
  // Only first 6 arguments are passed as registers
  unsigned GPRegArgCount = X86RegisterUtils::GPR64ArgRegs64Bit.size();
  unsigned SSERegArgCount = X86RegisterUtils::SSEArgRegs64Bit.size();
  MachineFunction &MF = x86MIRaiser->getMF();
  Function *CurFunction = x86MIRaiser->getRaisedFunction();

  unsigned GPArgNum = 0;
  unsigned SSEArgNum = 0;
  for (auto &Arg : CurFunction->args()) {
    Type *ArgTy = Arg.getType();

    MCPhysReg ArgReg;
    if (ArgTy->isIntOrPtrTy()) {
      if (GPArgNum > GPRegArgCount)
        continue;
      ArgReg = X86RegisterUtils::GPR64ArgRegs64Bit[GPArgNum];
      GPArgNum++;
    } else if (ArgTy->isFloatingPointTy() ||
               (ArgTy->isVectorTy() &&
                ArgTy->getPrimitiveSizeInBits() == 128)) {
      if (SSEArgNum > SSERegArgCount)
        continue;
      ArgReg = X86RegisterUtils::SSEArgRegs64Bit[SSEArgNum];
      SSEArgNum++;
    } else {
      llvm_unreachable("Unhandled argument type in raised function type");
    }

    unsigned ArgTySzInBits = ArgTy->getPrimitiveSizeInBits();
    physRegDefsInMBB[ArgReg][0] = std::make_pair(ArgTySzInBits, nullptr);
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
        // EFLAGS bits are modeled as 1-bit registers. So, nothing to do if
        // Physreg is EFLAGS
        if ((PhysReg == X86::EFLAGS) || (PhysReg == X86::FPSW) ||
            (PhysReg == X86::FPCW))
          continue;

        unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);
        // No value assigned yet for the definition of SuperReg in CurMBBNo.
        // The value will be updated as the block is raised.
        if (isSSE2Instruction(MI.getOpcode())) {
          uint8_t InstrBitPrecision =
              getInstructionBitPrecision(MI.getDesc().TSFlags);
          physRegDefsInMBB[SuperReg][MBBNo] =
              std::make_pair(InstrBitPrecision, nullptr);
        } else {
          uint8_t PhysRegSzInBits = getPhysRegSizeInBits(PhysReg);
          physRegDefsInMBB[SuperReg][MBBNo] =
              std::make_pair(PhysRegSzInBits, nullptr);
        }
      }
    }
  }
}

// Record Val as the most recent definition of PhysReg in BasicBlock
// corresponding to MachinebasicBlock with number MBBNo. This is nothing but
// local value numbering (i.e., value numbering within the block
// corresponding to MBBNo.
bool X86RaisedValueTracker::setPhysRegSSAValue(unsigned int PhysReg, int MBBNo,
                                               Value *Val) {
  assert((PhysReg != X86::NoRegister) &&
         "Attempt to set value of an invalid register");
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);

  if (!Val->hasName() && PhysReg < X86::NUM_TARGET_REGS)
    Val->setName(x86MIRaiser->getRegisterInfo()->getName(PhysReg));
  physRegDefsInMBB[SuperReg][MBBNo].second = Val;
  if (Val->getType()->isFloatingPointTy()) {
    auto BitPrecision = Val->getType()->getPrimitiveSizeInBits();
    physRegDefsInMBB[SuperReg][MBBNo].first = BitPrecision;
  } else {
    physRegDefsInMBB[SuperReg][MBBNo].first =
        X86RegisterUtils::getPhysRegSizeInBits(PhysReg);
  }

  assert((physRegDefsInMBB[SuperReg][MBBNo].first != 0) &&
         "Found incorrect size of physical register");
  return true;
}

// This function looks for definition of PhysReg in MBBNo. If not found, it
// looks for reaching definitions along the predecessors of block MBBNo. It
// returns a vector of reaching definitions. If AllPreds is true, a
// vector of definitions reachable along all predecessors is returned. If
// AllPreds is not true, return those that are reachable .

std::vector<std::pair<int, Value *>>
X86RaisedValueTracker::getGlobalReachingDefs(unsigned int PhysReg, int MBBNo,
                                             bool AllPreds) {
  std::vector<std::pair<int, Value *>> ReachingDefs;
  // Recursively walk the predecessors of current block to get
  // the reaching definition for PhysReg.

  MachineFunction &MF = x86MIRaiser->getMF();
  MachineBasicBlock *CurMBB = MF.getBlockNumbered(MBBNo);
  // Look for the most recent definition of SuperReg in current block.
  const std::pair<int, Value *> LocalDef =
      getInBlockRegOrArgDefVal(PhysReg, MBBNo);

  if (LocalDef.second != nullptr) {
    assert((LocalDef.first == MBBNo) && "Inconsistent local def info found");
    ReachingDefs.push_back(LocalDef);
  } else {
    // For each of the predecessors find if SuperReg has a definition in its
    // reach tree.
    bool RDFound = true;
    for (auto P : CurMBB->predecessors()) {
      // Initialize a bit vector tracking visited bacic blocks.
      BitVector BlockVisited(MF.getNumBlockIDs(), false);
      SmallVector<MachineBasicBlock *, 8> WorkList;

      if (AllPreds && !RDFound)
        break;
      // Visit an unvisited predecessor P
      if (BlockVisited[P->getNumber()])
        continue;
      else
        WorkList.push_back(P);

      // New path being traversed. Set RDFound to be false
      RDFound = false;
      while (!WorkList.empty()) {
        MachineBasicBlock *PredMBB = WorkList.pop_back_val();
        int CurPredMBBNo = PredMBB->getNumber();
        if (!BlockVisited[CurPredMBBNo]) {
          // Mark block as visited
          BlockVisited.set(CurPredMBBNo);
          const std::pair<int, Value *> ReachInfo =
              getInBlockRegOrArgDefVal(PhysReg, CurPredMBBNo);

          // if reach info found or if CurPredMBB has a definition of SuperReg,
          // record it
          if (ReachInfo.first != INVALID_MBB) {
            ReachingDefs.push_back(ReachInfo);
            RDFound = true;
          } else {
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

    // If reaching definitions along all predecessors is requested, but were not
    // found, clear the return list
    if (AllPreds && !RDFound)
      ReachingDefs.clear();
  }

  // Clean up any duplicate entries in ReachingDefs
  if (ReachingDefs.size() > 1) {
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

std::pair<int, Value *>
X86RaisedValueTracker::getInBlockRegOrArgDefVal(unsigned int PhysReg,
                                                int MBBNo) {
  // Always convert PhysReg to the 64-bit version.
  unsigned int SuperReg = x86MIRaiser->find64BitSuperReg(PhysReg);

  Value *DefValue = nullptr;
  int DefMBBNo = INVALID_MBB;
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
      assert((mbbToValMapIter->second.first != 0) &&
             "Found incorrect size of physical register");
      DefMBBNo = mbbToValMapIter->first;
      DefValue = mbbToValMapIter->second.second;
    }
  }
  // If MBBNo is entry and ReachingDef was not found, check to see
  // if this is an argument value.
  if ((DefValue == nullptr) && (MBBNo == 0)) {
    int pos = x86MIRaiser->getArgumentNumber(PhysReg);

    // If PReg is an argument register, get its value from function
    // argument list.
    if (pos > 0) {
      Function *RaisedFunction = x86MIRaiser->getRaisedFunction();

      int actualPos = pos;
      if (isSSE2Reg(PhysReg)) {
        // sse2 args are always after general purpose args
        // increment actualpos for every general purpose register encountered
        for (auto iter = RaisedFunction->arg_begin();
             iter != RaisedFunction->arg_end(); iter++) {
          if (!iter->getType()->isFloatingPointTy()) {
            actualPos++;
          }
        }
      }

      // Get the value only if the function has an argument at
      // pos.
      if (actualPos <= (int)(RaisedFunction->arg_size())) {
        Function::arg_iterator argIter =
            RaisedFunction->arg_begin() + actualPos - 1;
        DefMBBNo = 0;
        DefValue = argIter;
      }
    }
  }

  return std::make_pair(DefMBBNo, DefValue);
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
      assert((mbbToValMapIter->second.first != 0) &&
             "Found incorrect size of physical register");
      return mbbToValMapIter->second.first;
    }
  }
  // MachineBasicBlock with MBBNo does not define SuperReg.
  return 0;
}

// Get the reaching definition of PhysReg. This function looks for
// reaching definition in block MBBNo. If not found, walks its predecessors
// to find all reaching definitions. If the reaching definitions are different,
// the register is promoted to a stack slot. In other words, a stack slot is
// created, all the reaching definitions are stored in the basic blocks that
// define them. In the current basic block, use of this register is raised
// as load from the the stack slot. If AllPreds is true (default is false),
// perform the stack promotions only if PhysReg is reachable along all
// predecessors of MBBNo or is defined in MBBNo. If AnySubReg is false (which is
// the default), the return value is ensured to be of type with size of PhysReg.

Value *X86RaisedValueTracker::getReachingDef(unsigned int PhysReg, int MBBNo,
                                             bool AllPreds, bool AnySubReg) {
  MachineFunction &MF = x86MIRaiser->getMF();
  LLVMContext &Ctxt(MF.getFunction().getContext());
  Value *RetValue = nullptr;

  std::vector<std::pair<int, Value *>> ReachingDefs;
  const ModuleRaiser *MR = x86MIRaiser->getModuleRaiser();
  ReachingDefs = getGlobalReachingDefs(PhysReg, MBBNo, AllPreds);
  int RDVecSz = ReachingDefs.size();
  // If there are more than one distinct incoming reaching defs
  if (RDVecSz > 1) {
    // 1. Allocate stack slot with type general enough to hold any of the
    //    reaching values
    // 2. store each of the incoming values in that stack slot. cast the value
    //    as needed.
    // 3. load from the stack slot
    // 4. Return loaded value - RetValue

    // 1. Allocate stack slot
    const DataLayout &DL = MR->getModule()->getDataLayout();
    unsigned allocaAddrSpace = DL.getAllocaAddrSpace();

    // Get the super-type of all reaching definition values
    Type *AllocTy = nullptr;
    // If an incoming def is null and the type is not of floating-point type
    bool HasUnknownReachingDef = false;
    for (auto RD : ReachingDefs) {
      if (RD.second == nullptr) {
        // we might not have found a incoming edge that tells us if we're
        // dealing with int or floating point types -> continue for now
        HasUnknownReachingDef = true;
        continue;
      }

      if (RD.second->getType()->isIntegerTy()) {
        Type *Ty = RD.second->getType();
        if ((AllocTy == nullptr) ||
            (Ty->getPrimitiveSizeInBits() > AllocTy->getPrimitiveSizeInBits()))
          AllocTy = Ty;
      } else if (RD.second->getType()->isFloatingPointTy() ||
                 RD.second->getType()->isVectorTy()) {
        // We know that FP types are stored in a 128 bit stack slot, so we don't
        // need to further process the reaching value list
        AllocTy = VectorType::get(Type::getInt32Ty(Ctxt), 4, false);
        break;
      } else {
        HasUnknownReachingDef = true;
      }
    }

    // if we have an unknown reaching def and we don't already have a value
    // that's greater than the largest int value
    if (HasUnknownReachingDef &&
        (AllocTy == nullptr || AllocTy->getPrimitiveSizeInBits() < 64)) {
      // Any null value is stored in a 64-bit stack slot.
      // Note that a null value implies that this is an incoming edge from a
      // block that is not yet raised. This will be recorded and handled
      // later. So, assume the type to be the most generic, i.e., 64-bit.
      AllocTy = Type::getInt64Ty(Ctxt);
    }

    Align typeAlign(DL.getPrefTypeAlignment(AllocTy));
    auto typeSize =
        isEflagBit(PhysReg) ? 1 : AllocTy->getPrimitiveSizeInBits() / 8;

    const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
    StringRef PhysRegName;
    if (isEflagBit(PhysReg)) {
      PhysRegName = StringRef(getEflagName(PhysReg));
    } else {
      PhysRegName = TRI->getRegAsmName(PhysReg);
    }

    // Create alloca instruction to allocate stack slot
    AllocaInst *Alloca = new AllocaInst(AllocTy, allocaAddrSpace, 0, typeAlign,
                                        PhysRegName + "-SKT-LOC");

    // Create a stack slot associated with the alloca instruction of size 8
    unsigned int StackFrameIndex = MF.getFrameInfo().CreateStackObject(
        typeSize, typeAlign, true /* isSpillSlot */, Alloca);

    // Compute size of new stack object.
    const MachineFrameInfo &MFI = MF.getFrameInfo();
    // Size of currently allocated object size
    int64_t ObjectSize = MFI.getObjectSize(StackFrameIndex);
    // Get the offset of the top of stack. Note that stack objects in MFI are
    // not sorted by offset. So we need to walk the stack objects to find the
    // offset of the top stack object.
    int64_t StackTopOffset = 0;
    for (int StackIndex = MFI.getObjectIndexBegin();
         StackIndex < MFI.getObjectIndexEnd(); StackIndex++) {
      int64_t ObjOffset = MFI.getObjectOffset(StackIndex);
      if (ObjOffset < StackTopOffset)
        StackTopOffset = ObjOffset;
    }
    int64_t Offset = StackTopOffset - ObjectSize;

    // Set object size.
    MF.getFrameInfo().setObjectOffset(StackFrameIndex, Offset);

    // Add the alloca instruction to entry block
    x86MIRaiser->insertAllocaInEntryBlock(Alloca, Offset, StackFrameIndex);

    // If PhysReg is defined in MBBNo, store the defined value in the
    // newly created stack slot.
    std::pair<int, Value *> MBBNoRDPair =
        getInBlockRegOrArgDefVal(PhysReg, MBBNo);
    Value *DefValue = MBBNoRDPair.second;
    if (DefValue != nullptr) {
      BasicBlock &RaisedBB = x86MIRaiser->getRaisedFunction()->getEntryBlock();
      new StoreInst(DefValue, Alloca, &RaisedBB);
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
        x86MIRaiser->recordDefsToPromote(PhysReg, MBBVal.first, Alloca);
      } else {
        Instruction *I = dyn_cast<Instruction>(MBBVal.second);
        if (!hasRODataAccess(Alloca) && (I != nullptr)) {
          Alloca->copyMetadata(*I);
        }
        StoreInst *StInst = x86MIRaiser->promotePhysregToStackSlot(
            PhysReg, MBBVal.second, MBBVal.first, Alloca);
        assert(StInst != nullptr &&
               "Failed to promote reaching definition to stack slot");
      }
    }
    // 3. load from the stack slot for use in current block
    Instruction *LdReachingVal = new LoadInst(
        Alloca->getType()->getPointerElementType(), Alloca, "", false, Align());
    LdReachingVal =
        setInstMetadataRODataContent(dyn_cast<LoadInst>(LdReachingVal));
    // Insert load instruction
    x86MIRaiser->getRaisedBasicBlock(MF.getBlockNumbered(MBBNo))
        ->getInstList()
        .push_back(LdReachingVal);
    if (!AnySubReg) {
      // Ensure that the loaded value has the type that can be represented by
      // PhysReg - unless specifically not requested, such as during argument
      // liveness discovery.
      Type *RegType = (isEflagBit(PhysReg))
                          ? Type::getInt1Ty(Ctxt)
                          : x86MIRaiser->getPhysRegType(PhysReg);
      Type *LdReachingValType = LdReachingVal->getType();
      assert((LdReachingValType->isIntegerTy() ||
              LdReachingValType->isFloatingPointTy() ||
              LdReachingValType->isVectorTy()) &&
             "Unhandled type mismatch of reaching register definition");
      if (RegType != LdReachingValType) {
        auto BB = x86MIRaiser->getRaisedBasicBlock(MF.getBlockNumbered(MBBNo));
        if (isSSE2Reg(PhysReg)) {
          assert(LdReachingValType->getPrimitiveSizeInBits() == 128 &&
                 "Expected FP/vector types to be stored in 128 bit stack slot");
        } else {
          // Create cast instruction
          Instruction *CInst = CastInst::Create(
              CastInst::getCastOpcode(LdReachingVal, false, RegType, false),
              LdReachingVal, RegType);
          BB->getInstList().push_back(CInst);
          LdReachingVal = CInst;
        }
      }
    }
    RetValue = LdReachingVal;
    // Record that PhysReg is now defined as load from stack location in
    // current MBB with MBBNo.
    setPhysRegSSAValue(PhysReg, MBBNo, RetValue);
  } else if (ReachingDefs.size() == 1)
    // Just return the value of the single reaching definition
    RetValue = ReachingDefs[0].second;

  return RetValue;
}

// Set the value of FlagBit to BitVal based on the value computed by TestVal.
// If the test corresponding to FlagBit is true, it is set, else it is cleared.
// TestVal is the raised value of MI.
bool X86RaisedValueTracker::testAndSetEflagSSAValue(unsigned int FlagBit,
                                                    const MachineInstr &MI,
                                                    Value *TestResultVal) {
  assert((FlagBit >= X86RegisterUtils::EFLAGS::CF) &&
         (FlagBit < X86RegisterUtils::EFLAGS::UNDEFINED) &&
         "Unknown EFLAGS bit specified");

  int MBBNo = MI.getParent()->getNumber();
  MachineFunction &MF = x86MIRaiser->getMF();
  LLVMContext &Ctx = MF.getFunction().getContext();

  BasicBlock *RaisedBB =
      x86MIRaiser->getRaisedBasicBlock(MF.getBlockNumbered(MBBNo));

  unsigned int ResTyNumBits =
      TestResultVal->getType()->getPrimitiveSizeInBits();
  switch (FlagBit) {
  case X86RegisterUtils::EFLAGS::ZF: {
    Value *ZeroVal = ConstantInt::get(Ctx, APInt(ResTyNumBits, 0));
    // Set ZF - test if TestVal is 0
    Instruction *ZFTest =
        new ICmpInst(CmpInst::Predicate::ICMP_EQ, TestResultVal, ZeroVal,
                     X86RegisterUtils::getEflagName(FlagBit));

    RaisedBB->getInstList().push_back(ZFTest);
    physRegDefsInMBB[FlagBit][MBBNo].second = ZFTest;
  } break;
  case X86RegisterUtils::EFLAGS::SF: {
    Value *ZeroVal = ConstantInt::get(Ctx, APInt(ResTyNumBits, 0));
    // Set SF - test if TestVal is signed
    auto ShiftVal = ConstantInt::get(Ctx, APInt(ResTyNumBits, 1));
    auto HighBitSetVal =
        ConstantInt::get(Ctx, APInt(ResTyNumBits, ResTyNumBits - 1));
    // Compute 1 << (ResTyNumBits - 1)
    auto ShiftLeft = ConstantExpr::getShl(ShiftVal, HighBitSetVal, true, true);

    // Create the instruction
    //      and SubInst, ShiftLeft
    Instruction *AndInst =
        BinaryOperator::CreateAnd(ShiftLeft, TestResultVal, "highbit");
    RaisedBB->getInstList().push_back(AndInst);
    // Compare result of logical and operation to find if bit 31 is set SF
    // accordingly
    Instruction *SFTest =
        new ICmpInst(CmpInst::Predicate::ICMP_NE, AndInst, ZeroVal,
                     X86RegisterUtils::getEflagName(FlagBit));
    RaisedBB->getInstList().push_back(SFTest);
    physRegDefsInMBB[FlagBit][MBBNo].second = SFTest;
  } break;
  case X86RegisterUtils::EFLAGS::OF: {
    auto IntrinsicOF = Intrinsic::not_intrinsic;
    Value *TestArg[2];
    Module *M = x86MIRaiser->getModuleRaiser()->getModule();

    // If TestVal is a cast value, it is most likely cast to match the
    // source of the compare instruction. Get to the value prior to casting.
    CastInst *castInst = dyn_cast<CastInst>(TestResultVal);
    while (castInst) {
      TestResultVal = castInst->getOperand(0);
      castInst = dyn_cast<CastInst>(TestResultVal);
    }

    Instruction *TestInst = dyn_cast<Instruction>(TestResultVal);
    assert((TestInst != nullptr) && "Expect test producing instruction while "
                                    "testing and setting of EFLAGS");

    if ((x86MIRaiser->instrNameStartsWith(MI, "SUB")) ||
        (x86MIRaiser->instrNameStartsWith(MI, "CMP")) ||
        (x86MIRaiser->instrNameStartsWith(MI, "SBB"))) {
      IntrinsicOF = Intrinsic::ssub_with_overflow;
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values unexpected");

      // Construct a call to get overflow value upon comparison of test arg
      // values
      Function *ValueOF =
          Intrinsic::getDeclaration(M, IntrinsicOF, TestArg[0]->getType());
      CallInst *GetOF = CallInst::Create(
          cast<FunctionType>(
              cast<PointerType>(ValueOF->getType())->getElementType()),
          ValueOF, ArrayRef<Value *>(TestArg));
      RaisedBB->getInstList().push_back(GetOF);
      // Extract OF and set it
      physRegDefsInMBB[FlagBit][MBBNo].second =
          ExtractValueInst::Create(GetOF, 1, "OF", RaisedBB);
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ADD")) {
      IntrinsicOF = Intrinsic::sadd_with_overflow;
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values unexpected");

      // Construct a call to get overflow value upon comparison of test arg
      // values
      Function *ValueOF =
          Intrinsic::getDeclaration(M, IntrinsicOF, TestArg[0]->getType());
      CallInst *GetOF = CallInst::Create(
          cast<FunctionType>(
              cast<PointerType>(ValueOF->getType())->getElementType()),
          ValueOF, ArrayRef<Value *>(TestArg));
      RaisedBB->getInstList().push_back(GetOF);
      // Extract OF and set it
      physRegDefsInMBB[FlagBit][MBBNo].second =
          ExtractValueInst::Create(GetOF, 1, "OF", RaisedBB);
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ROL")) {
      // OF flag is defined only for 1-bit rotates i.e., ROLr*1).
      // It is undefined in all other cases. OF flag is set to the exclusive OR
      // of CF after rotate and the most-significant bit of the result.
      if ((MI.getNumExplicitOperands() == 2) &&
          (MI.findTiedOperandIdx(1) == 0)) {
        // CF flag receives a copy of the bit that was shifted from one end to
        // the other. Find the least-significant bit, which is the bit shifted
        // from the most-significant location.
        // NOTE: CF computation is repeated here, just to be sure.
        // Construct constant 1 of TestResultVal type
        Value *OneValue = ConstantInt::get(TestResultVal->getType(), 1);
        // Get LSB of TestResultVal using the instruction and TestResultVal, 1
        Instruction *ResultLSB = BinaryOperator::CreateAnd(
            TestResultVal, OneValue, "lsb-result", RaisedBB);
        // Set ResultCF to 1 if LSB is 1, else to 0
        Instruction *ResultCF = new ICmpInst(CmpInst::Predicate::ICMP_EQ,
                                             ResultLSB, OneValue, "CF-RES");
        // Insert compare instruction
        RaisedBB->getInstList().push_back(ResultCF);

        // Get most-significant bit of the result (i.e., TestResultVal)
        auto ResultNumBits = TestResultVal->getType()->getPrimitiveSizeInBits();
        // Construct a constant with only the most significant bit set
        Value *LeftShift =
            ConstantInt::get(TestResultVal->getType(), (ResultNumBits - 1));
        // Get (1 << LeftShift)
        Value *MSBSetConst = BinaryOperator::CreateShl(OneValue, LeftShift,
                                                       "MSB-CONST", RaisedBB);
        // Get (TestResultVal & MSBSetConst) to get the most significant bit of
        // TestResultVal
        Instruction *ResultMSB = BinaryOperator::CreateAnd(
            TestResultVal, MSBSetConst, "MSB-RES", RaisedBB);
        // Check if MSB is non-zero
        Value *ZeroValue = ConstantInt::get(ResultMSB->getType(), 0);
        // Generate (ResultMSB != 0) to indicate MSB
        Instruction *MSBIsSet = new ICmpInst(CmpInst::Predicate::ICMP_NE,
                                             ResultMSB, ZeroValue, "MSB-SET");
        RaisedBB->getInstList().push_back(dyn_cast<Instruction>(MSBIsSet));
        // Generate XOR ResultCF, MSBIsSet to compute OF
        Instruction *ResultOF =
            BinaryOperator::CreateXor(ResultCF, MSBIsSet, "OF", RaisedBB);
        physRegDefsInMBB[FlagBit][MBBNo].second = ResultOF;
      }
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ROR")) {
      // OF flag is defined only for 1-bit rotates i.e., RORr*1).
      // It is undefined in all other cases. OF flag is set to the exclusive OR
      // of the two most-significant bits of the result.
      if ((MI.getNumExplicitOperands() == 2) &&
          (MI.findTiedOperandIdx(1) == 0)) {
        // Find most-significant bit of result.
        Value *OneValue = ConstantInt::get(TestResultVal->getType(), 1);

        // Get most-significant bit of the result (i.e., TestResultVal)
        auto ResultNumBits = TestResultVal->getType()->getPrimitiveSizeInBits();
        // Construct a constant with only the most significant bit set
        Value *LeftShift =
            ConstantInt::get(TestResultVal->getType(), (ResultNumBits - 1));
        // Get (1 << LeftShift)
        Value *BitSetConst = BinaryOperator::CreateShl(OneValue, LeftShift,
                                                       "MSB-CONST", RaisedBB);
        // Get (TestResultVal & MSBSetConst) to get the most significant bit of
        // TestResultVal
        Instruction *BitSetResult = BinaryOperator::CreateAnd(
            TestResultVal, BitSetConst, "MSB-RES", RaisedBB);
        // Check if MSB is non-zero
        Value *ZeroValue = ConstantInt::get(BitSetResult->getType(), 0);
        // Generate (BitSetResult != 0) to indicate MSB
        Instruction *MSBIsSet = new ICmpInst(
            CmpInst::Predicate::ICMP_NE, BitSetResult, ZeroValue, "MSB-SET");
        RaisedBB->getInstList().push_back(dyn_cast<Instruction>(MSBIsSet));

        // Construct a constant with only the pre-MSB location set
        LeftShift =
            ConstantInt::get(TestResultVal->getType(), (ResultNumBits - 2));
        // Get (1 << LeftShift)
        BitSetConst = BinaryOperator::CreateShl(OneValue, LeftShift,
                                                "Pre-MSB-CONST", RaisedBB);
        // Get (TestResultVal & BitSetConst) to get the pre-most significant bit
        // of TestResultVal
        BitSetResult = BinaryOperator::CreateAnd(TestResultVal, BitSetConst,
                                                 "Pre-MSB-RES", RaisedBB);
        // Check if pre-MSB is non-zero
        // Generate (BitSetResult != 0) to indicate pre-MSB
        Instruction *PreMSBIsSet =
            new ICmpInst(CmpInst::Predicate::ICMP_NE, BitSetResult, ZeroValue,
                         "Pre-MSB-SET");
        RaisedBB->getInstList().push_back(dyn_cast<Instruction>(PreMSBIsSet));

        // Generate XOR MSBIsSet, PreMSBIsSet to compute OF
        Instruction *ResultOF =
            BinaryOperator::CreateXor(MSBIsSet, PreMSBIsSet, "OF", RaisedBB);
        physRegDefsInMBB[FlagBit][MBBNo].second = ResultOF;
      }
    } else if (x86MIRaiser->instrNameStartsWith(MI, "TEST")) {
      // Set CF to 0 and make type to i1
      physRegDefsInMBB[FlagBit][MBBNo].second =
          ConstantInt::get(Type::getInt1Ty(Ctx), 0);
    } else {
      LLVM_DEBUG(MI.dump());
      assert(false && "*** EFLAGS update abstraction not handled yet");
    }
  } break;
  case X86RegisterUtils::EFLAGS::PF: {
    // PF is set if least-significant byte of the result contains an even number
    // of 1 bits; else the flag is cleared.
    Module *M = x86MIRaiser->getModuleRaiser()->getModule();

    Value *SrcVal = TestResultVal;

    if (SrcVal->getType()->isIntegerTy() &&
        SrcVal->getType()->getIntegerBitWidth() > 8) {
      // Get least-significant byte
      Instruction *LSB = BinaryOperator::CreateAnd(
          SrcVal, ConstantInt::get(SrcVal->getType(), 0xff));
      RaisedBB->getInstList().push_back(LSB);
      SrcVal = LSB;
    }

    Function *IntrinsicFunc =
        Intrinsic::getDeclaration(M, Intrinsic::ctpop, SrcVal->getType());
    Value *IntrinsicCallArgs[] = {SrcVal};
    Instruction *ParityValue =
        CallInst::Create(IntrinsicFunc, ArrayRef<Value *>(IntrinsicCallArgs));

    // Add the intrinsic call instruction
    RaisedBB->getInstList().push_back(ParityValue);

    Instruction *ParityEvenBit = BinaryOperator::CreateAnd(
        ParityValue, ConstantInt::get(ParityValue->getType(), 1));
    RaisedBB->getInstList().push_back(ParityEvenBit);

    // Test if ParityEvenBit is Zero
    Value *ZeroValue =
        ConstantInt::get(ParityEvenBit->getType(), 0, false /* isSigned */);
    Instruction *PFTest = new ICmpInst(CmpInst::Predicate::ICMP_EQ,
                                       ParityEvenBit, ZeroValue, "PF");
    RaisedBB->getInstList().push_back(PFTest);
    physRegDefsInMBB[FlagBit][MBBNo].second = PFTest;
  } break;
  case X86RegisterUtils::EFLAGS::CF: {
    Module *M = x86MIRaiser->getModuleRaiser()->getModule();
    Value *NewCF = nullptr;

    // If TestVal is a cast value, it is most likely cast to match the
    // source of the compare instruction. Get to the value prior to casting.
    CastInst *castInst = dyn_cast<CastInst>(TestResultVal);
    while (castInst) {
      TestResultVal = castInst->getOperand(0);
      castInst = dyn_cast<CastInst>(TestResultVal);
    }

    if (x86MIRaiser->instrNameStartsWith(MI, "NEG")) {
      // Set CF to 0 if source operand is 0 else to 1
      Instruction *TestInst = dyn_cast<Instruction>(TestResultVal);
      assert((TestInst != nullptr) && "Expect test producing instruction while "
                                      "testing and setting of EFLAGS");
      // TestInst should be a sub 0, val instruction
      assert((TestInst->getOpcode() == Instruction::Sub) &&
             "Expect NEG to be raised as SUB");
      // Get the arguments of the sub instruction that computes the neg
      Value *TestArg[2];
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values not expected");
      // A zero value of appropriate type
      Value *ZeroVal =
          ConstantFP::getZeroValueForNegation(TestArg[1]->getType());
      assert(((TestArg[0] == ZeroVal)) &&
             "Expected zero value of sub instruction while updating CF for NEG "
             "instruction");
      // Set ZF - test if TestVal is not equal to 0 - to get the CF bit value.
      Instruction *CmpInst =
          new ICmpInst(CmpInst::Predicate::ICMP_NE, TestArg[0], ZeroVal,
                       X86RegisterUtils::getEflagName(FlagBit));
      RaisedBB->getInstList().push_back(CmpInst);
      NewCF = CmpInst;
    } else if ((x86MIRaiser->instrNameStartsWith(MI, "SUB")) ||
               (x86MIRaiser->instrNameStartsWith(MI, "CMP")) ||
               (x86MIRaiser->instrNameStartsWith(MI, "SBB"))) {
      Value *TestArg[2];
      Instruction *TestInst = dyn_cast<Instruction>(TestResultVal);
      assert((TestInst != nullptr) && "Expect test producing instruction while "
                                      "testing and setting of EFLAGS");
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values not expected");
      // Construct a call to get carry flag value upon comparison of test arg
      // values
      Function *ValueCF = Intrinsic::getDeclaration(
          M, Intrinsic::usub_with_overflow, TestArg[0]->getType());
      CallInst *GetCF = CallInst::Create(
          cast<FunctionType>(
              cast<PointerType>(ValueCF->getType())->getElementType()),
          ValueCF, ArrayRef<Value *>(TestArg));
      RaisedBB->getInstList().push_back(GetCF);
      // Extract flag-bit
      NewCF = ExtractValueInst::Create(GetCF, 1, "CF", RaisedBB);
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ADD")) {
      Value *TestArg[2];
      Instruction *TestInst = dyn_cast<Instruction>(TestResultVal);
      assert((TestInst != nullptr) && "Expect test producing instruction while "
                                      "testing and setting of EFLAGS");
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values not expected");
      // Construct a call to get carry flag value upon comparison of test arg
      // values
      Function *ValueCF = Intrinsic::getDeclaration(
          M, Intrinsic::uadd_with_overflow, TestArg[0]->getType());
      CallInst *GetCF = CallInst::Create(
          cast<FunctionType>(
              cast<PointerType>(ValueCF->getType())->getElementType()),
          ValueCF, ArrayRef<Value *>(TestArg));
      RaisedBB->getInstList().push_back(GetCF);
      // Extract flag-bit
      NewCF = ExtractValueInst::Create(GetCF, 1, "CF", RaisedBB);
    } else if (x86MIRaiser->instrNameStartsWith(MI, "SHRD")) {
      // TestInst should have been a call to intrinsic llvm.fshr.*
      CallInst *IntrinsicCall = dyn_cast<CallInst>(TestResultVal);
      assert((IntrinsicCall != nullptr) &&
             (IntrinsicCall->getFunctionType()->getNumParams() == 3) &&
             "Expected call instruction with three arguments not found");
      Value *DstArgVal = IntrinsicCall->getArgOperand(1);
      Value *CountArgVal = IntrinsicCall->getArgOperand(2);
      // If count is 1 or greater, CF is filled with the last bit shifted out
      // of destination operand.
      Value *ZeroVal = ConstantInt::get(
          Ctx, APInt(CountArgVal->getType()->getPrimitiveSizeInBits(), 0));
      Instruction *CountValTest =
          new ICmpInst(CmpInst::Predicate::ICMP_SGT, CountArgVal, ZeroVal,
                       "shrd_cf_count_cmp");
      RaisedBB->getInstList().push_back(CountValTest);

      // The last bit shifted out of destination operand is the
      // least-significant N'th bit where N == CountVal. So get that value as
      // follows:
      // if (DestVal & (1 << N))
      //   CF = 1
      // else
      //   CF = 0
      Instruction *ShlInst =
          BinaryOperator::CreateShl(ConstantInt::get(CountArgVal->getType(), 1),
                                    CountArgVal, "shrd_cf_count_shift");
      RaisedBB->getInstList().push_back(ShlInst);
      Instruction *AndInst =
          BinaryOperator::CreateAnd(DstArgVal, ShlInst, "shrd_cf_count_and");

      RaisedBB->getInstList().push_back(AndInst);

      // Is it Zero
      Instruction *NewCFInst =
          new ICmpInst(CmpInst::Predicate::ICMP_SGT, AndInst, ZeroVal,
                       "shrd_cf_count_shft_out");

      RaisedBB->getInstList().push_back(NewCFInst);

      Value *OldCF = physRegDefsInMBB[FlagBit][MBBNo].second;

      // Select the value of CF based on Count value being > 0
      Instruction *SelectCF =
          SelectInst::Create(CountValTest, NewCFInst, OldCF, "shrd_cf_update");
      RaisedBB->getInstList().push_back(SelectCF);

      NewCF = SelectCF;
    } else if (x86MIRaiser->instrNameStartsWith(MI, "SHL")) {
      Value *DstArgVal = nullptr;
      Value *CountArgVal = nullptr;
      // If this is a funnel shift
      if (x86MIRaiser->instrNameStartsWith(MI, "SHLD")) {
        // TestInst should have been a call to intrinsic llvm.fshl.*
        CallInst *IntrinsicCall = dyn_cast<CallInst>(TestResultVal);
        assert((IntrinsicCall != nullptr) &&
               (IntrinsicCall->getFunctionType()->getNumParams() == 3) &&
               "Expected call instruction with three arguments not found");
        DstArgVal = IntrinsicCall->getArgOperand(0);
        CountArgVal = IntrinsicCall->getArgOperand(2);
      } else {
        // TestInst should have been shl instruction
        BinaryOperator *BinOp = dyn_cast<BinaryOperator>(TestResultVal);
        assert((BinOp != nullptr) && (BinOp->getNumOperands() == 2) &&
               "Expected a shl binary operator with 2 operands");
        DstArgVal = BinOp->getOperand(0);
        CountArgVal = BinOp->getOperand(1);
      }
      // If count is 1 or greater, CF is filled with the last bit shifted out
      // of destination operand.
      Value *ZeroVal = ConstantInt::get(
          Ctx, APInt(CountArgVal->getType()->getPrimitiveSizeInBits(), 0));
      Instruction *CountValTest =
          new ICmpInst(CmpInst::Predicate::ICMP_SGT, CountArgVal, ZeroVal,
                       "shrd_cf_count_cmp");
      RaisedBB->getInstList().push_back(CountValTest);

      // The last bit shifted out of destination operand is the
      // least-significant N'th bit where TypeSize =
      // DstArgVal->getType()->getPrimitiveSizeInBits()) and
      // N == (TypeSize - CountVal).
      // So get that value as follows:
      // if (DestVal & (1 << N))
      //   CF = 1
      // else
      //   CF = 0
      Value *TypeSizeVal =
          ConstantInt::get(CountArgVal->getType(),
                           DstArgVal->getType()->getPrimitiveSizeInBits());

      Instruction *ShiftAmt =
          BinaryOperator::CreateSub(TypeSizeVal, CountArgVal);

      RaisedBB->getInstList().push_back(ShiftAmt);

      // Shift 1 by ShiftAmt
      Instruction *ShlInst =
          BinaryOperator::CreateShl(ConstantInt::get(CountArgVal->getType(), 1),
                                    ShiftAmt, "shld_cf_count_shift");
      RaisedBB->getInstList().push_back(ShlInst);

      Instruction *AndInst =
          BinaryOperator::CreateAnd(DstArgVal, ShlInst, "shld_cf_count_and");

      RaisedBB->getInstList().push_back(AndInst);

      // Is it Zero
      Instruction *NewCFInst =
          new ICmpInst(CmpInst::Predicate::ICMP_SGT, AndInst, ZeroVal,
                       "shld_cf_count_shft_out");

      RaisedBB->getInstList().push_back(NewCFInst);

      Value *OldCF = physRegDefsInMBB[FlagBit][MBBNo].second;
      // Select the value of CF based on Count value being > 0
      Instruction *SelectCF =
          SelectInst::Create(CountValTest, NewCFInst, OldCF, "shld_cf_update");
      RaisedBB->getInstList().push_back(SelectCF);

      NewCF = SelectCF;
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ROL")) {
      // CF flag receives a copy of the bit that was shifted from one end to
      // the other. Find the least-significant bit, which is the bit shifted
      // from the most-significant location.
      // NOTE: CF computation is repeated here, just to be sure.
      // Construct constant 1 of TestResultVal type
      Value *OneValue = ConstantInt::get(TestResultVal->getType(), 1);
      // Get LSB of TestResultVal using the instruction and TestResultVal, 1
      Instruction *ResultLSB = BinaryOperator::CreateAnd(
          TestResultVal, OneValue, "lsb-result", RaisedBB);
      // Set ResultCF to 1 if LSB is 1, else to 0
      Instruction *ResultCF = new ICmpInst(CmpInst::Predicate::ICMP_EQ,
                                           ResultLSB, OneValue, "CF-RES");
      // Insert compare instruction
      RaisedBB->getInstList().push_back(ResultCF);
      NewCF = ResultCF;
    } else if (x86MIRaiser->instrNameStartsWith(MI, "ROR")) {
      // CF flag receives a copy of the bit that was shifted from one end to
      // the other. Find the most-significant bit, which is the bit shifted
      // from the least-significant location.
      // Find most-significant bit of result.
      Value *OneValue = ConstantInt::get(TestResultVal->getType(), 1);

      // Get most-significant bit of the result (i.e., TestResultVal)
      auto ResultNumBits = TestResultVal->getType()->getPrimitiveSizeInBits();
      // Construct a constant with only the most significant bit set
      Value *LeftShift =
          ConstantInt::get(TestResultVal->getType(), (ResultNumBits - 1));
      // Get (1 << LeftShift)
      Value *BitSetConst =
          BinaryOperator::CreateShl(OneValue, LeftShift, "MSB-CONST", RaisedBB);
      // Get (TestResultVal & MSBSetConst) to get the most significant bit of
      // TestResultVal
      Instruction *BitSetResult = BinaryOperator::CreateAnd(
          TestResultVal, BitSetConst, "MSB-RES", RaisedBB);
      // Check if MSB is non-zero
      Value *ZeroValue = ConstantInt::get(BitSetResult->getType(), 0);
      // Generate (BitSetResult != 0) to indicate MSB
      Instruction *MSBIsSet = new ICmpInst(CmpInst::Predicate::ICMP_NE,
                                           BitSetResult, ZeroValue, "MSB-SET");
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(MSBIsSet));
      NewCF = MSBIsSet;
    } else if (x86MIRaiser->instrNameStartsWith(MI, "IMUL")) {
      // TestInst should have been mul instruction
      BinaryOperator *TestInst = dyn_cast<BinaryOperator>(TestResultVal);
      assert((TestInst != nullptr) && (TestInst->getNumOperands() == 2) &&
             "Expected a mul binary operator with 2 operands");
      Value *TestArg[2];
      TestArg[0] = TestInst->getOperand(0);
      TestArg[1] = TestInst->getOperand(1);
      assert((TestArg[0]->getType() == TestArg[1]->getType()) &&
             "Differing types of test values unexpected");

      // Construct a call to get overflow value upon comparison of test arg
      // values.
      Function *ValueOF = Intrinsic::getDeclaration(
          M, Intrinsic::smul_with_overflow, TestArg[0]->getType());
      CallInst *GetOF = CallInst::Create(
          cast<FunctionType>(
              cast<PointerType>(ValueOF->getType())->getElementType()),
          ValueOF, ArrayRef<Value *>(TestArg));
      RaisedBB->getInstList().push_back(GetOF);
      // Extract OF and set both OF and CF to the same value
      auto NewOF = ExtractValueInst::Create(GetOF, 1, "OF", RaisedBB);
      physRegDefsInMBB[EFLAGS::OF][MBBNo].second = NewOF;
      NewCF = NewOF;
      // Set OF to the same value of CF
      physRegDefsInMBB[EFLAGS::OF][MBBNo].second = NewCF;
    } else if (x86MIRaiser->instrNameStartsWith(MI, "TEST")) {
      // Set CF to 0 and make type to i1
      NewCF = ConstantInt::get(Type::getInt1Ty(Ctx), 0);
    } else {
      LLVM_DEBUG(MI.dump());
      assert(false &&
             "*** Abstraction of CF for the instruction not handled yet");
    }
    // Update CF.
    assert((NewCF != nullptr) && "Value to update CF not found");
    physRegDefsInMBB[FlagBit][MBBNo].second = NewCF;
  } break;

  // TODO: Add code to test for other flags
  default:
    assert(false && "Unhandled EFLAGS bit specified");
  }
  // EFLAGS bit size is 1
  physRegDefsInMBB[FlagBit][MBBNo].first = 1;
  return true;
}

// Set FlagBit to Value.
bool X86RaisedValueTracker::setEflagValue(unsigned int FlagBit, int MBBNo,
                                          Value *Val) {
  assert((FlagBit >= X86RegisterUtils::EFLAGS::CF) &&
         (FlagBit < X86RegisterUtils::EFLAGS::UNDEFINED) &&
         "Unknown EFLAGS bit specified");
  Val->setName(X86RegisterUtils::getEflagName(FlagBit));
  physRegDefsInMBB[FlagBit][MBBNo].second = Val;
  // EFLAGS bit size is 1
  physRegDefsInMBB[FlagBit][MBBNo].first = 1;
  return true;
}

// Set FlagBit to 1 if Set is true else to 0.
bool X86RaisedValueTracker::setEflagBoolean(unsigned int FlagBit, int MBBNo,
                                            bool Set) {
  assert((FlagBit >= X86RegisterUtils::EFLAGS::CF) &&
         (FlagBit < X86RegisterUtils::EFLAGS::UNDEFINED) &&
         "Unknown EFLAGS bit specified");
  LLVMContext &Ctx = x86MIRaiser->getMF().getFunction().getContext();
  Value *Val = Set ? ConstantInt::getTrue(Ctx) : ConstantInt::getFalse(Ctx);
  setEflagValue(FlagBit, MBBNo, Val);
  return true;
}

// Call getReachingDef.
Value *X86RaisedValueTracker::getEflagReachingDef(unsigned int FlagBit,
                                                  int MBBNo) {
  assert((FlagBit >= X86RegisterUtils::EFLAGS::CF) &&
         (FlagBit < X86RegisterUtils::EFLAGS::UNDEFINED) &&
         "Unknown EFLAGS bit specified");
  return getReachingDef(FlagBit, MBBNo);
}

// Cast SrcVal to the type of DstVal, if their types are different.
// Return the cast instruction upon inserting it at the end of InsertBlock
Value *X86RaisedValueTracker::castValue(Value *SrcValue, Type *DstTy,
                                        BasicBlock *InsertBlock,
                                        bool SrcIsSigned) {
  if (SrcValue->getType() != DstTy) {
    // If SrcValue is signed, Dst is also signed
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(SrcValue, SrcIsSigned, DstTy, SrcIsSigned),
        SrcValue, DstTy);
    // Set RODataIndex metadata
    setInstMetadataRODataIndex(SrcValue, CInst);
    // Add the cast instruction RaisedBB.
    InsertBlock->getInstList().push_back(CInst);
    return CInst;
  }

  return SrcValue;
}

// Reinterpret a SSE register value to another type
// This function does not modify any bits, it only zero-extends or truncates
// passed values
// Example inputs:
// SrcVal = float 0x3fc00000 (= 1.5), DstTy = double
// Return Val = double 0x000000003fc00000
Value *
X86RaisedValueTracker::reinterpretSSERegValue(Value *SrcVal, Type *DstTy,
                                              BasicBlock *InsertBlock,
                                              Instruction *InsertBefore) {
#define INSERT_INSTRUCTION(Inst)                                               \
  do {                                                                         \
    if (InsertBefore != nullptr) {                                             \
      Inst->insertBefore(InsertBefore);                                        \
    } else {                                                                   \
      InsertBlock->getInstList().push_back(Inst);                              \
    }                                                                          \
  } while (0)

  assert((InsertBlock != nullptr || InsertBefore != nullptr) &&
         "Expected either InsertBlock or InsertBefore to be not null");

  if (SrcVal->getType() == DstTy) {
    return SrcVal;
  }

  Instruction *Result;
  if (SrcVal->getType()->getPrimitiveSizeInBits() >
      DstTy->getPrimitiveSizeInBits()) {
    Type *SrcTyVec =
        VectorType::get(DstTy,
                        SrcVal->getType()->getPrimitiveSizeInBits() /
                            DstTy->getPrimitiveSizeInBits(),
                        false);
    auto SrcVec = new BitCastInst(SrcVal, SrcTyVec);
    INSERT_INSTRUCTION(SrcVec);

    auto Zero = ConstantInt::get(Type::getInt64Ty(DstTy->getContext()), 0);
    Result = ExtractElementInst::Create(SrcVec, Zero);
  } else if (SrcVal->getType()->getPrimitiveSizeInBits() <
             DstTy->getPrimitiveSizeInBits()) {
    Type *SrcTyVec =
        VectorType::get(SrcVal->getType(),
                        DstTy->getPrimitiveSizeInBits() /
                            SrcVal->getType()->getPrimitiveSizeInBits(),
                        false);
    Value *SrcVec;
    if (SrcVal->getType()->isFloatingPointTy()) {
      SrcVec = ConstantFP::get(SrcTyVec, 0);
    } else {
      SrcVec = ConstantInt::get(SrcTyVec, 0);
    }

    auto Zero = ConstantInt::get(Type::getInt64Ty(DstTy->getContext()), 0);
    auto InsertElem = InsertElementInst::Create(SrcVec, SrcVal, Zero);
    INSERT_INSTRUCTION(InsertElem);

    Result = new BitCastInst(InsertElem, DstTy);
  } else {
    // same width, just bitcast
    Result = new BitCastInst(SrcVal, DstTy);
  }

  assert(Result->getType() == DstTy);

  INSERT_INSTRUCTION(Result);
  return Result;
#undef INSERT_INSTRUCTION
}

Type *X86RaisedValueTracker::getSSEInstructionType(const MachineInstr &MI,
                                                   LLVMContext &Ctx) {
  uint64_t TSFlags = MI.getDesc().TSFlags;

  if ((TSFlags & llvm::X86II::OpPrefixMask) == llvm::X86II::XS) {
    return Type::getFloatTy(Ctx);
  } else if ((TSFlags & llvm::X86II::OpPrefixMask) == llvm::X86II::XD) {
    return Type::getDoubleTy(Ctx);
  } else {
    auto Domain = (TSFlags >> llvm::X86II::SSEDomainShift) & 3;

    // X64BaseInfo.h does not define enums. X86InstrFormats.td specified
    // GenericDomain = 0 (non-SSE instruction)
    // SSEPackedSingle = 1
    // SSEPackedDouble = 2
    // SSEPackedInt = 3
    switch (Domain) {
    case 1:
      return VectorType::get(Type::getFloatTy(Ctx), 4, false);
    case 2:
      return VectorType::get(Type::getDoubleTy(Ctx), 2, false);
    case 3:
      return VectorType::get(Type::getInt32Ty(Ctx), 4, false);
    }
  }
  llvm_unreachable("Unhandled SSE type");
}

// If SrcValue is a ConstantExpr abstraction of rodata index, set metadata of
// Inst; if SrcValue is an instruction with rodata index metadata, copy it to
// Inst.
bool X86RaisedValueTracker::setInstMetadataRODataIndex(Value *SrcValue,
                                                       Instruction *Inst) {
  // String denoting rodata index metadata.
  // std::string RODataMDKindStr(RODATA_INDEX_MD_STR);
  // Check if SrcValue is an index into rodata
  if (auto RODataIndex = dyn_cast<ConstantExpr>(SrcValue)) {
    std::string OpcodeName(RODataIndex->getOpcodeName());
    if (OpcodeName.compare("getelementptr") == 0) {
      if (RODataIndex->getOperand(0)->getName().startswith("rodata_")) {
        assert(!hasRODataAccess(Inst) && "ROData annotation already exists");
        // Add metadata to indicate that this instruction uses rodata index.
        auto ROMD = ValueAsMetadata::get(SrcValue);
        Inst->setMetadata(
            RODATA_INDEX_MD_STR,
            MDNode::get(Inst->getContext(), ArrayRef<Metadata *>{ROMD}));
      }
    }
  } else if (auto InstUsingROData = dyn_cast<Instruction>(SrcValue)) {
    if (hasRODataAccess(InstUsingROData)) {
      assert(!hasRODataAccess(Inst) && "ROData annotation already exists");
      Inst->copyMetadata(*InstUsingROData);
    }
  }
  // TODO : Handle metadata propagation for other types as needed.
  // else {
  //  assert(false &&
  //         "Unhandled source type while setting rodata index metadata");
  // }
  return true;
}

// Set metadata of load instruction LdInst based on its source operand. If it is
// rodata content, return a new instruction that loads from appropriately
// relocated memory reference. If no relocation is needed, just return LdInst.
LoadInst *
X86RaisedValueTracker::setInstMetadataRODataContent(LoadInst *LdInst) {
  LoadInst *NewLdInst = LdInst;
  // Get the load address.
  Value *SrcValue = LdInst->getOperand(0);
  // Check if SrcValue is an index into rodata
  if (auto RODataIndex = dyn_cast<ConstantExpr>(SrcValue)) {
    std::string OpcodeName(RODataIndex->getOpcodeName());
    if (OpcodeName.compare("getelementptr") == 0) {
      if (RODataIndex->getOperand(0)->getName().startswith("rodata_")) {
        assert(!hasRODataAccess(LdInst) && "ROData annotation already exists");
        // Get metadata representing the rodata index. Note that this may NOT be
        // the rodata index represented by SrcValue. SrcValue may be an
        // expression representing the address computation based on this rodata
        // index.
        // Add metadata to indicate that this instruction abstracts rodata
        // content.
        auto ROMD = ValueAsMetadata::get(SrcValue);
        LdInst->setMetadata(
            RODATA_CONTENT_MD_STR,
            MDNode::get(LdInst->getContext(), ArrayRef<Metadata *>{ROMD}));
      }
    }
  } else if (auto SrcValueAsInst = dyn_cast<Instruction>(SrcValue)) {
    if (hasRODataAccess(SrcValueAsInst)) {
      assert(!hasRODataAccess(LdInst) && "ROData annotation already exists");
      // Get metadata representing the rodata index. Note that this may NOT be
      // the rodata index represented by SrcValue. SrcValue may be an
      // instruction representing the address computation based on this rodata
      // index.
      auto ROMD = SrcValueAsInst->getMetadata(RODATA_INDEX_MD_STR);
      if (ROMD != nullptr) {
        // Set the metadata kind to rodata content
        LdInst->setMetadata(
            RODATA_CONTENT_MD_STR,
            MDNode::get(LdInst->getContext(), ArrayRef<Metadata *>{ROMD}));
      } else if ((ROMD = SrcValueAsInst->getMetadata(RODATA_CONTENT_MD_STR))) {
        // If SrcValue is itself rodata content, relocate the value by adjusting
        // the offset appropriately.
        Value *RODataRebaseOffset = getRelocOffsetForRODataAddress(SrcValue);
        // Add the rebase value to SrcValue;
        BasicBlock *RaisedBB = SrcValueAsInst->getParent();
        assert(SrcValue->getType()->isPointerTy() &&
               "Expect source of load instruction to be of pointer type");
        // Cast the pointer type to integer type to facilitate addition of
        // offset
        Value *ModSrcValue =
            castValue(SrcValue, RODataRebaseOffset->getType(), RaisedBB);
        ModSrcValue = BinaryOperator::CreateAdd(ModSrcValue, RODataRebaseOffset,
                                                "rodata-rebase", RaisedBB);
        // Note LdInst is a load instruction and is not yet inserted into
        // the raised basic block. So, simply create a new one in its place and
        // delete the old one. Cast the relocated value to the same type of
        // LdInst. Cast the relocated SrcValue.
        Type *LdPtrTy = SrcValue->getType();
        ModSrcValue = castValue(ModSrcValue, LdPtrTy, RaisedBB);
        // NOTE: Do not insert the new instruction as the caller of this
        // function is expected to do so.
        NewLdInst = new LoadInst(LdPtrTy->getPointerElementType(), ModSrcValue,
                                 "rodata-reloc", LdInst->isVolatile(),
                                 Align(LdInst->getAlignment()));
        // Copy metadata of the new load instruction to indicate that the loaded
        // value is content of rodata by propagating the metadata from
        // SrcValueAsInst.
        NewLdInst->copyMetadata(*SrcValueAsInst);
        LdInst->deleteValue();
      } else {
        assert(false && "Unexpected metadata kind found");
      }
    }
  }
  // TODO : Handle metadata propagation for other types as needed.
  // else {
  //  assert(false &&
  //         "Unhandled source type while setting rodata content metadata");
  // }

  return NewLdInst;
}

// Annotate GlobalVariable GV with rodata section start value in source binary
bool X86RaisedValueTracker::setGVMetadataRODataInfo(GlobalVariable *GV,
                                                    uint64_t RODataSecStart) {
  // Create ConstantAsMetadata
  LLVMContext &Ctx(GV->getContext());
  ConstantAsMetadata *CMD = ConstantAsMetadata::get(
      ConstantInt::get(Type::getInt64Ty(Ctx), RODataSecStart));
  GV->setMetadata(RODATA_SEC_INFO_MD_STR,
                  MDNode::get(Ctx, ArrayRef<Metadata *>{CMD}));
  return true;
}

// Generate code to return offset value if rodata address falls within rodata
// section. Else return zero value
Value *X86RaisedValueTracker::getRelocOffsetForRODataAddress(
    Value *RaisedRODataAddrVal) {
  LLVMContext &Ctx(RaisedRODataAddrVal->getContext());
  Value *Zero64BitValue =
      ConstantInt::get(Type::getInt64Ty(Ctx), 0, false /* isSigned */);
  // Set the default offset value to be zero.
  Value *RelocRODataAddrVal = Zero64BitValue;

  if (Instruction *RaisedRODataAddrAsInst =
          dyn_cast<Instruction>(RaisedRODataAddrVal)) {
    // Get rodata related metadata associated with RaisedRODataAddrAsInst to
    // find the rodata information associated with this abstracted value.
    MDNode *RaisedRODataInstMD =
        RaisedRODataAddrAsInst->getMetadata(RODATA_CONTENT_MD_STR);
    assert(RaisedRODataInstMD != nullptr &&
           "Expect metadata assocated with rodata - not found");
    assert(RaisedRODataInstMD->getNumOperands() == 1 &&
           "Expect one operand of rodata metadata");
    // Get the metadata as MetadataAsvalue
    auto RaisedRODataMDAsVal =
        MetadataAsValue::get(RaisedRODataAddrAsInst->getContext(),
                             RaisedRODataInstMD->getOperand(0).get());
    assert(RaisedRODataMDAsVal != nullptr && "Failed to get metadata as value");

    // Get the Value encapsulated by metadata.
    Value *RaisedRODataExprValue =
        cast<ValueAsMetadata>(RaisedRODataMDAsVal->getMetadata())->getValue();
    ConstantExpr *RaisedRODataIndex =
        dyn_cast<ConstantExpr>(RaisedRODataExprValue);
    assert(RaisedRODataIndex != nullptr &&
           "Not found expected expected metadata of type constant expression");
    std::string OpcodeName(RaisedRODataIndex->getOpcodeName());
    // Note that metadata contains the reference to the value that indexes into
    // rodata section content of the source binary abstracted (i.e., raised) as
    // a global array of bytes.
    if (OpcodeName.compare("getelementptr") == 0) {
      if (RaisedRODataIndex->getOperand(0)->getName().startswith("rodata_")) {
        auto RaisedRODataArrValue = RaisedRODataIndex->getOperand(0);
        // Get the global variable corresponding to constant expression
        // representing abstracted rodata array.
        if (GlobalVariable *RaisedRODataArrGV =
                dyn_cast<GlobalVariable>(RaisedRODataArrValue)) {
          Function *Func = RuntimeFunction::getOrCreateSecOffsetCalcFunction(
              *RaisedRODataAddrAsInst->getParent()->getModule());

          // Global variable representing rodata array is annotated with
          // rodata section start value of the source binary.
          auto RaisedRODataSecInfoMD =
              RaisedRODataArrGV->getMetadata(RODATA_SEC_INFO_MD_STR);
          assert(RaisedRODataSecInfoMD != nullptr &&
                 "Expected rodata section info - not found");
          assert(RaisedRODataArrGV->getNumOperands() == 1 &&
                 RaisedRODataArrGV->getOperand(0)->getType()->isArrayTy() &&
                 RaisedRODataArrGV->getOperand(0)
                     ->getType()
                     ->getArrayElementType()
                     ->isIntegerTy(8) &&
                 "Expect rodata to be abstracted as an array of bytes - not "
                 "found");
          // Construct a value representing rodata section start in source
          // binary
          Value *SrcBinaryRODataSecStartValue = cast<ConstantInt>(
              cast<ConstantAsMetadata>(RaisedRODataSecInfoMD->getOperand(0))
                  ->getValue());
          // Construct a value representing rodata section size in source
          // binary
          uint64_t SrcBinaryRODataSecSz = RaisedRODataArrGV->getOperand(0)
                                              ->getType()
                                              ->getArrayNumElements();
          Type *Int64Ty = Type::getInt64Ty(Ctx);
          Value *SrcBinaryRODataSecSzVal =
              ConstantInt::get(Int64Ty, SrcBinaryRODataSecSz);
          // Create arguments to call rodata address relocation function.
          // Get the block to add code to.
          BasicBlock *RaisedBB = RaisedRODataAddrAsInst->getParent();
          // Cast RaisedRODataAddrVal to 64-bit value to facilitate
          // comparison
          Value *InVal = castValue(RaisedRODataAddrVal, Int64Ty, RaisedBB);
          // Cast global variable address
          auto RaisedRODataArrGVAddrVal =
              castValue(RaisedRODataArrGV, Int64Ty, RaisedBB);

          // Call the relocation function
          RelocRODataAddrVal = CallInst::Create(
              Func,
              {InVal, SrcBinaryRODataSecStartValue, SrcBinaryRODataSecSzVal,
               RaisedRODataArrGVAddrVal},
              "rodata-translate", RaisedBB);
        } else {
          assert(
              false &&
              "Expected global variable corresponding to rodata - not found");
        }
      }
    } else
      llvm_unreachable("Unhandled type of rodata found");
  }
  return RelocRODataAddrVal;
}

#undef DEBUG_TYPE
