//==-- X86MachineInstructionRaiser.h - Binary raiser utility llvm-mctoll =====//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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

using MBBNumToBBMap = std::map<unsigned int, BasicBlock *>;

class X86MachineInstructionRaiser : public MachineInstructionRaiser {
public:
  X86MachineInstructionRaiser() = delete;
  X86MachineInstructionRaiser(MachineFunction &machFunc, Module &m,
                              const ModuleRaiser *mr, MCInstRaiser *mcir);
  bool raise();

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
  // Map of physical registers -> virtual registers
  std::map<unsigned int, unsigned int> physToVirtMap;

  // Map of physical registers -> Value * created
  std::map<unsigned int, Value *> physToValueMap;
  // std::stack<Value *> FPURegisterStack;
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
  bool raiseMachineInstr(MachineInstr &, BasicBlock *);
  // Cleanup MachineBasicBlocks
  bool deleteNOOPInstrMI(MachineBasicBlock &, MachineBasicBlock::iterator);
  bool deleteNOOPInstrMF();

  // Raise specific classes of instructions
  bool raisePushInstruction(const MachineInstr &);
  bool raisePopInstruction(const MachineInstr &);

  bool raiseMemRefMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseReturnMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseGenericMachineInstr(const MachineInstr &, BasicBlock *);

  bool raiseConvertBWWDDQMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseConvertWDDQQOMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseLEAMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseMoveRegToRegMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseMoveImmToRegMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseBinaryOpRegToRegMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseBinaryOpImmToRegMachineInstr(const MachineInstr &, BasicBlock *);
  bool raiseSetCCMachineInstr(const MachineInstr &, BasicBlock *);

  bool raiseCompareMachineInstr(const MachineInstr &, BasicBlock *, bool,
                                Value *);

  bool raiseCallMachineInstr(const MachineInstr &, BasicBlock *);

  bool raiseMoveToMemInstr(const MachineInstr &, BasicBlock *, Value *);
  bool raiseMoveFromMemInstr(const MachineInstr &, BasicBlock *, Value *);
  bool raiseBinaryOpMemToRegInstr(const MachineInstr &, BasicBlock *, Value *);
  bool raiseDivideInstr(const MachineInstr &, BasicBlock *, Value *);
  bool raiseLoadIntToFloatRegInstr(const MachineInstr &, BasicBlock *, Value *);
  bool raiseStoreIntToFloatRegInstr(const MachineInstr &, BasicBlock *,
                                    Value *);
  bool raiseFPURegisterOpInstr(const MachineInstr &, BasicBlock *);

  bool raiseBranchMachineInstrs();
  bool raiseDirectBranchMachineInstr(ControlTransferInfo *);
  bool raiseIndirectBranchMachineInstr(ControlTransferInfo *);

  // Method to record information that is used in a second pass
  // to raise control transfer instructions in a second pass.
  bool recordMachineInstrInfo(const MachineInstr &, BasicBlock *);

  bool insertAllocaInEntryBlock(Instruction *alloca);

  // FPU Stack access functions
  void FPURegisterStackPush(Value *);
  void FPURegisterStackPop();
  Value *FPURegisterStackGetValueAt(int8_t);
  void FPURegisterStackSetValueAt(int8_t, Value *);
  Value *FPURegisterStackTop();

  // Helper functions
  int getMemoryRefOpIndex(const MachineInstr &);
  Value *getGlobalVariableValueAt(const MachineInstr &, uint64_t, BasicBlock *);
  const Value *getOrCreateGlobalRODataValueAtOffset(int64_t Offset,
                                                    Type *OffsetTy);
  Value *getMemoryAddressExprValue(const MachineInstr &, BasicBlock *);
  Value *createPCRelativeAccesssValue(const MachineInstr &, BasicBlock *);

  bool changePhysRegToVirtReg(MachineInstr &);

  unsigned int find64BitSuperReg(unsigned int);
  Value *findPhysRegSSAValue(unsigned int);
  Value *matchSSAValueToSrcRegSize(const MachineInstr &mi, unsigned SrcOpIndex,
                                   BasicBlock *curBlock);

  std::pair<std::map<unsigned int, Value *>::iterator, bool>
  updatePhysRegSSAValue(unsigned int PhysReg, Value *);
  Type *getFunctionReturnType();
  Type *getReturnTypeFromMBB(MachineBasicBlock &MBB);
  Function *getTargetFunctionAtPLTOffset(const MachineInstr &, uint64_t);
  Value *getStackAllocatedValue(const MachineInstr &, BasicBlock *,
                                X86AddressMode &);
  int getArgumentNumber(unsigned PReg);
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &);

  Value *getRegValue(unsigned);
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_X86_X86ELIMINATEPROLOGEPILOG_H
