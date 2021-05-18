//===-- X86MachineInstructionRaiser.h ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of X86MachineInstructionRaiser
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_X86_X86MACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_X86_X86MACHINEINSTRUCTIONRAISER_H

#include "MachineInstructionRaiser.h"
#include "X86AdditionalInstrInfo.h"
#include "llvm/IR/Instructions.h"

// Type alias for Map of MBBNo -> BasicBlock * used to keep track of
// MachineBasicBlock and corresponding raised BasicBlock
using MBBNumToBBMap = std::map<unsigned int, BasicBlock *>;

// Tuple of <PhysReg, DefiningMBBNo, Alloca>
// When promoting reaching definitions there may be situations where the
// predecessor block that defines a reaching definition may not yet have
// been raised. This tuple represents the Alloca slot to which
// the value of PhysReg defined in DefiningMBB should be stored once it is
// raised.
using PhysRegMBBValTuple = std::tuple<unsigned int, unsigned int, Value *>;

// MCPhysReg set
using MCPhysRegSet = std::set<MCPhysReg>;

// Map of 64-bit super register -> size of register access
using MCPhysRegSizeMap = std::map<MCPhysReg, uint16_t>;

// Forward declaration of X86RaisedValueTracker
class X86RaisedValueTracker;

namespace llvm {
class X86Subtarget;
class X86InstrInfo;
class X86RegisterInfo;
struct X86AddressMode;
} // namespace llvm

class X86MachineInstructionRaiser : public MachineInstructionRaiser {
public:
  X86MachineInstructionRaiser() = delete;
  X86MachineInstructionRaiser(MachineFunction &MF, const ModuleRaiser *MR,
                              MCInstRaiser *MIR);
  bool raise() override;

  // Return the 64-bit super-register of PhysReg.
  unsigned int find64BitSuperReg(unsigned int PhysReg);
  // Return the Type of the physical register.
  Type *getPhysRegType(unsigned int PhysReg);
  // Return type of the floating point physical register
  Type *getPhysSSERegType(unsigned int PhysReg, uint8_t BitPrecision);

  bool insertAllocaInEntryBlock(Instruction *alloca, int StackOffset,
                                int MFIndex);
  BasicBlock *getRaisedBasicBlock(const MachineBasicBlock *);
  bool recordDefsToPromote(unsigned PhysReg, unsigned MBBNo, Value *Alloca);
  StoreInst *promotePhysregToStackSlot(int PhysReg, Value *ReachingValue,
                                       int MBBNo, Instruction *Alloca);
  int getArgumentNumber(unsigned PReg) override;
  auto getRegisterInfo() const { return x86RegisterInfo; }
  bool instrNameStartsWith(const MachineInstr &MI, StringRef name) const;
  X86RaisedValueTracker *getRaisedValues() { return raisedValues; }

private:
  X86RaisedValueTracker *raisedValues;

  // Set of reaching definitions that were not promoted during since defining
  // block is not yet raised and need to be promoted upon raising all blocks.
  std::set<PhysRegMBBValTuple> reachingDefsToPromote;

  // A map of MBB number to known defined registers along with the access size
  // at the exit of the MBB.
  std::map<int, MCPhysRegSizeMap> PerMBBDefinedPhysRegMap;

  static const uint8_t FPUSTACK_SZ = 8;
  struct {
    int8_t TOP;
    Value *Regs[FPUSTACK_SZ];
  } FPUStack;

  // A map of MachineFunctionBlock number to BasicBlock *
  MBBNumToBBMap mbbToBBMap;

  // Since MachineFrameInfo does not represent stack object ordering, we
  // maintain a shadow stack indexed and sorted by descending order of stack
  // offset of objects allocated on the stack.
  std::map<int64_t, int> ShadowStackIndexedByOffset;

  // Commonly used LLVM data structures during this phase
  MachineRegisterInfo &machineRegInfo;
  const X86Subtarget &x86TargetInfo;
  const X86InstrInfo *x86InstrInfo;
  const X86RegisterInfo *x86RegisterInfo;

  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &) override;
  Value *getRegOrArgValue(unsigned PReg, int MBBNo) override;

  bool raiseMachineFunction();
  FunctionType *getRaisedFunctionPrototype() override;
  // This raises MachineInstr to MachineInstruction
  bool raiseMachineInstr(MachineInstr &);

  // Raise specific classes of instructions
  bool raisePushInstruction(const MachineInstr &);
  bool raisePopInstruction(const MachineInstr &);

  bool raiseMemRefMachineInstr(const MachineInstr &);
  bool raiseReturnMachineInstr(const MachineInstr &);
  bool raiseGenericMachineInstr(const MachineInstr &);

  bool raiseConvertBWWDDQMachineInstr(const MachineInstr &);
  bool raiseConvertWDDQQOMachineInstr(const MachineInstr &);
  bool raiseLEAMachineInstr(const MachineInstr &);
  bool raiseMoveRegToRegMachineInstr(const MachineInstr &);
  bool raiseMoveImmToRegMachineInstr(const MachineInstr &);

  bool raiseBinaryOpRegToRegMachineInstr(const MachineInstr &);
  bool raiseBinaryOpImmToRegMachineInstr(const MachineInstr &);
  bool raiseBinaryOpMRIOrMRCEncodedMachineInstr(const MachineInstr &MI);
  bool raiseBinaryOpMemToRegInstr(const MachineInstr &, Value *);
  bool raiseSetCCMachineInstr(const MachineInstr &);
  bool raiseCallMachineInstr(const MachineInstr &);
  bool raiseCompareMachineInstr(const MachineInstr &, bool, Value *);
  bool raiseInplaceMemOpInstr(const MachineInstr &, Value *);
  bool raiseMoveToMemInstr(const MachineInstr &, Value *);
  bool raiseMoveFromMemInstr(const MachineInstr &, Value *);
  bool raiseDivideInstr(const MachineInstr &, Value *);
  bool raiseLoadIntToFloatRegInstr(const MachineInstr &, Value *);
  bool raiseStoreIntToFloatRegInstr(const MachineInstr &, Value *);
  bool raiseFPURegisterOpInstr(const MachineInstr &);
  bool raiseSSECompareMachineInstr(const MachineInstr &);
  bool raiseSSEConvertPrecisionMachineInstr(const MachineInstr &);

  bool raiseBranchMachineInstrs();
  bool raiseDirectBranchMachineInstr(ControlTransferInfo *);
  bool raiseIndirectBranchMachineInstr(ControlTransferInfo *);

  Value *getMemoryRefValue(const MachineInstr &);

  // Helper functions
  // Cleanup MachineBasicBlocks
  static bool deleteNOOPInstrMI(MachineBasicBlock &,
                                MachineBasicBlock::iterator);
  bool deleteNOOPInstrMF();
  bool unlinkEmptyMBBs();
  // Adjust sizes of stack allocated objects
  bool createFunctionStackFrame();

  // Method to record information that is used in a second pass
  // to raise control transfer instructions in a second pass.
  bool recordMachineInstrInfo(const MachineInstr &);

  // Raise Machine Jumptable
  bool raiseMachineJumpTable();

  Value *getSwitchCompareValue(MachineBasicBlock &mbb);

  // FPU Stack access functions
  void FPURegisterStackPush(Value *);
  void FPURegisterStackPop();
  Value *FPURegisterStackGetValueAt(int8_t);
  void FPURegisterStackSetValueAt(int8_t, Value *);
  Value *FPURegisterStackTop();

  int getMemoryRefOpIndex(const MachineInstr &);
  Value *getGlobalVariableValueAt(const MachineInstr &, uint64_t);
  Value *getOrCreateGlobalRODataValueAtOffset(int64_t Offset,
                                              BasicBlock *InsertBlock);
  Value *getMemoryAddressExprValue(const MachineInstr &);
  Value *createPCRelativeAccesssValue(const MachineInstr &);

  bool changePhysRegToVirtReg(MachineInstr &);

  Value *getPhysRegValue(const MachineInstr &, unsigned);

  Type *getFunctionReturnType();
  Type *getReachingReturnType(const MachineBasicBlock &MBB);
  Type *getReturnTypeFromMBB(const MachineBasicBlock &MBB, bool &HasCall);
  Function *getTargetFunctionAtPLTOffset(const MachineInstr &, uint64_t);
  Value *getStackAllocatedValue(const MachineInstr &, X86AddressMode &, bool);
  Value *getRegOperandValue(const MachineInstr &mi, unsigned OperandIndex);

  bool handleUnpromotedReachingDefs();

  const MachineInstr *
  getPhysRegDefiningInstInBlock(int PhysReg, const MachineInstr *StartMI,
                                const MachineBasicBlock *MBB,
                                unsigned StopAtInstProp, bool &HasStopInst);

  void addRegisterToFunctionLiveInSet(MCPhysRegSet &CurLiveSet, unsigned Reg);
  int64_t getBranchTargetMBBNumber(const MachineInstr &MI);
  Function *getCalledFunction(const MachineInstr &MI);

  Type *getImmOperandType(const MachineInstr &MI, unsigned int OpIndex);
  uint8_t getPhysRegOperandSize(const MachineInstr &MI, unsigned int OpIndex);
  Type *getPhysRegOperandType(const MachineInstr &MI, unsigned int OpIndex);
  bool isPushToStack(const MachineInstr &MI) const;
  bool isPopFromStack(const MachineInstr &MI) const;
  bool isEffectiveAddrValue(Value *Val);

  std::vector<JumpTableInfo> jtList;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_X86_X86MACHINEINSTRUCTIONRAISER_H
