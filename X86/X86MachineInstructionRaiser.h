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
  X86MachineInstructionRaiser(MachineFunction &machFunc, const ModuleRaiser *mr,
                              MCInstRaiser *mcir);
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
  bool raiseMachineInstr(MachineInstr &);
  // Cleanup MachineBasicBlocks
  bool deleteNOOPInstrMI(MachineBasicBlock &, MachineBasicBlock::iterator);
  bool deleteNOOPInstrMF();

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

  bool raiseCompareMachineInstr(const MachineInstr &, bool, Value *);

  bool raiseCallMachineInstr(const MachineInstr &);

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

  bool insertAllocaInEntryBlock(Instruction *alloca);

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

  unsigned int find64BitSuperReg(unsigned int);
  Value *findPhysRegSSAValue(unsigned int);
  Value *matchSSAValueToSrcRegSize(const MachineInstr &mi, unsigned SrcOpIndex);

  std::pair<std::map<unsigned int, Value *>::iterator, bool>
  updatePhysRegSSAValue(unsigned int PhysReg, Value *);
  Type *getFunctionReturnType();
  Type *getReturnTypeFromMBB(MachineBasicBlock &MBB);
  Function *getTargetFunctionAtPLTOffset(const MachineInstr &, uint64_t);
  Value *getStackAllocatedValue(const MachineInstr &, X86AddressMode &, bool);
  int getArgumentNumber(unsigned PReg);
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &);

  Value *getRegValue(unsigned PReg);
  Value *getRegOperandValue(const MachineInstr &mi, unsigned OperandIndex);

  BasicBlock *getRaisedBasicBlock(const MachineBasicBlock *);

  // JumpTableBlock - the Jumptable case.
  using JumpTableBlock = std::pair<ConstantInt *, MachineBasicBlock *>;

  struct JumpTableInfo {
    // Jump table index
    unsigned jtIdx;

    // Conditon Machine BasicBlock.
    MachineBasicBlock *conditionMBB;

    // Default Machine BasicBlock.
    MachineBasicBlock *df_MBB;
  };

  std::vector<JumpTableInfo> jtList;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_X86_X86ELIMINATEPROLOGEPILOG_H
