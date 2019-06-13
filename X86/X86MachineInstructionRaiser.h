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

/*
 * Type alias for Map of MBBNo -> BasicBlock * used to keep track of
 * MachineBasicBlock and corresponding raised BasicBlock
 */
using MBBNumToBBMap = std::map<unsigned int, BasicBlock *>;

// Tuple of <PhysReg, DefiningMBBNo, Alloca>
// When promoting reaching definitions there may be situations where the
// predecessor block that defines a reaching definition may not yet have
// been raised. This tuple represents the Alloca slot to which
// the value of PhysReg defined in DefiningMBB should be stored once it is
// raised.
using PhysRegMBBValTuple = std::tuple<unsigned int, unsigned int, Value *>;

// Forward declaration of X86RaisedValueTracker
class X86RaisedValueTracker;

class X86MachineInstructionRaiser : public MachineInstructionRaiser {
public:
  X86MachineInstructionRaiser() = delete;
  X86MachineInstructionRaiser(MachineFunction &machFunc, const ModuleRaiser *mr,
                              MCInstRaiser *mcir);
  bool raise();

  unsigned int find64BitSuperReg(unsigned int);
  bool insertAllocaInEntryBlock(Instruction *alloca);
  BasicBlock *getRaisedBasicBlock(const MachineBasicBlock *);
  bool recordDefsToPromote(unsigned PhysReg, unsigned MBBNo, Value *Alloca);
  StoreInst *promotePhysregToStackSlot(int PhysReg, Value *ReachingValue,
                                       int MBBNo, AllocaInst *Alloca);

private:
  // Bit positions used for individual status flags of EFLAGS register.
  // Note : only those that are currently used are represented here.
  enum {
    EFLAGS_CF = 0,
    EFLAGS_PF = 2,
    EFLAGS_AF = 4,
    EFLAGS_ZF = 6,
    EFLAGS_SF = 7,
    EFLAGS_OF = 11,
    EFLAGS_UNDEFINED = 32
  };

  X86RaisedValueTracker *raisedValues;

  // Set of reaching definitions that were not promoted during since defining
  // block is not yet raised and need to be promoted upon raising all blocks.
  std::set<PhysRegMBBValTuple> reachingDefsToPromote;

  static const uint8_t FPUSTACK_SZ = 8;
  struct {
    int8_t TOP;
    Value *Regs[FPUSTACK_SZ];
  } FPUStack;

  // A map of MachineFunctionBlock number to BasicBlock *
  MBBNumToBBMap mbbToBBMap;

  // Commonly used LLVM data structures during this phase
  MachineRegisterInfo &machineRegInfo;
  const X86Subtarget &x86TargetInfo;
  const X86InstrInfo *x86InstrInfo;
  const X86RegisterInfo *x86RegisterInfo;

  bool raiseMachineFunction();
  FunctionType *getRaisedFunctionPrototype();
  // This raises MachineInstr to MachineInstruction
  bool raiseMachineInstr(MachineInstr &);
  // Cleanup MachineBasicBlocks
  bool deleteNOOPInstrMI(MachineBasicBlock &, MachineBasicBlock::iterator);
  bool deleteNOOPInstrMF();
  bool unlinkEmptyMBBs();

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
  bool raiseSetCCMachineInstr(const MachineInstr &);
  bool raiseCallMachineInstr(const MachineInstr &);

  bool raiseCompareMachineInstr(const MachineInstr &, bool, Value *);
  bool raiseNotOpMemInstr(const MachineInstr &, Value *);
  bool raiseMoveToMemInstr(const MachineInstr &, Value *);
  bool raiseMoveFromMemInstr(const MachineInstr &, Value *);
  bool raiseBinaryOpMemToRegInstr(const MachineInstr &, Value *);
  bool raiseDivideInstr(const MachineInstr &, Value *);
  bool raiseLoadIntToFloatRegInstr(const MachineInstr &, Value *);
  bool raiseStoreIntToFloatRegInstr(const MachineInstr &, Value *);
  bool raiseFPURegisterOpInstr(const MachineInstr &);

  bool raiseBranchMachineInstrs();
  bool raiseDirectBranchMachineInstr(ControlTransferInfo *);
  bool raiseIndirectBranchMachineInstr(ControlTransferInfo *);

  // Adjust sizes of stack allocated objects
  bool adjustStackAllocatedObjects();

  // Method to record information that is used in a second pass
  // to raise control transfer instructions in a second pass.
  bool recordMachineInstrInfo(const MachineInstr &);

  // Raise Machine Jumptable
  bool raiseMachineJumpTable();

  Instruction *raiseConditonforJumpTable(MachineBasicBlock &mbb);

  // FPU Stack access functions
  void FPURegisterStackPush(Value *);
  void FPURegisterStackPop();
  Value *FPURegisterStackGetValueAt(int8_t);
  void FPURegisterStackSetValueAt(int8_t, Value *);
  Value *FPURegisterStackTop();

  // Helper functions
  int getMemoryRefOpIndex(const MachineInstr &);
  Value *getGlobalVariableValueAt(const MachineInstr &, uint64_t);
  const Value *getOrCreateGlobalRODataValueAtOffset(int64_t Offset,
                                                    Type *OffsetTy);
  Value *getMemoryAddressExprValue(const MachineInstr &);
  Value *createPCRelativeAccesssValue(const MachineInstr &);

  bool changePhysRegToVirtReg(MachineInstr &);

  Value *matchSSAValueToSrcRegSize(const MachineInstr &mi, unsigned SrcOpIndex);

  Type *getFunctionReturnType();
  Type *getReturnTypeFromMBB(MachineBasicBlock &MBB);
  Function *getTargetFunctionAtPLTOffset(const MachineInstr &, uint64_t);
  Value *getStackAllocatedValue(const MachineInstr &, X86AddressMode &, bool);
  int getArgumentNumber(unsigned PReg);
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &);

  Value *getRegOrArgValue(unsigned PReg, int MBBNo);
  Value *getRegOperandValue(const MachineInstr &mi, unsigned OperandIndex);

  bool handleUnpromotedReachingDefs();

  bool hasPhysRegDefInBlock(int PhysReg, const MachineInstr *StartMI,
                            const MachineBasicBlock *MBB,
                            unsigned StopAtInstProp, bool &HasStopInst);

  // Return the Type of the physical register.
  Type *getPhysRegType(unsigned int PhysReg);

  bool appendInstToBB(BasicBlock *, Instruction *);

  std::vector<JumpTableInfo> jtList;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_X86_X86ELIMINATEPROLOGEPILOG_H
