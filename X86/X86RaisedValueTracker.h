//===-- X86RaisedValueTracker.h ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of X86RaisedValueTracker
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_X86_X86RAISEDVALUETRACKER_H
#define LLVM_TOOLS_LLVM_MCTOLL_X86_X86RAISEDVALUETRACKER_H

#include "X86MachineInstructionRaiser.h"

namespace llvm {
namespace mctoll {

// This class encapsulates all the necessary bookkeeping and look up of SSA
// values constructed while a MachineFunction is raised.

// Begin - Type aliases of data structures used to facilitate promotion of
// registers to stack slots.

// DefRegSizeInBits, Value pair
using DefRegSzValuePair = std::pair<uint8_t, Value *>;

// Map of MBBNo -> DefRegSzValuePair
using MBBNoToValueMap = std::map<unsigned int, DefRegSzValuePair>;

// Map of physical registers -> MBBNoToValueMap.
// Pictorially, this map looks as follows:
//     { SuperReg1 -> { MBBNo_1 -> { <PhysReg_1_Sz, Val_A> },
//                      MBBNo_2 -> { <PhysReg_2_Sz, Val_B> }
//                      MBBNo_3 -> { <PhysReg_3_Sz, Val_C> } },
//       SuperReg2 -> { MBBNo_4 -> { <PhysReg_4_Sz, Val_X> },
//                      MBBNo_2 -> { <PhysReg_2_Sz, Val_Y> } },
//       ......
//      }
// Each entry of this map has the following semantics:
// SuperReg is defined in MBBNo using Val as a sub-register of size
// PhysReg_Sz. E.g., SuperReg RAX may be actually defined as register of size 16
// (i.e. AX).
using PhysRegMBBValueDefMap = std::map<unsigned int, MBBNoToValueMap>;

class X86RaisedValueTracker {
public:
  X86RaisedValueTracker() = delete;
  X86RaisedValueTracker(X86MachineInstructionRaiser *);
  bool setPhysRegSSAValue(unsigned int PhysReg, int MBBNo, Value *Val);
  bool testAndSetEflagSSAValue(unsigned Flag, const MachineInstr &MI, Value *);
  bool setEflagBoolean(unsigned FlagBit, int MBBNo, bool Set);
  bool setEflagValue(unsigned FlagBit, int MBBNo, Value *);

  // Get the reaching definition of PhysReg. Perform any necessary stack
  // promotions. If AllPreds is true, perform the stack promotions only if
  // PhysReg is reachable along all predecessors of MBBNo or is defined in
  // MBBNo.
  Value *getReachingDef(unsigned int PhysReg, int MBBNo, bool AllPreds = false,
                        bool AnySubReg = false);
  Value *getEflagReachingDef(unsigned Flag, int MBBNo);

  // Return a vector of <MBBNo, Value*> pairs denoting the defining MBB numbers
  // and Values defined for PhysReg in the predecessors of MBBNo.
  std::vector<std::pair<int, Value *>>
  getGlobalReachingDefs(unsigned int PhysReg, int MBBNo, bool AllPreds = false);

  std::pair<int, Value *> getInBlockRegOrArgDefVal(unsigned int PhysReg,
                                                   int MBBNo);
  unsigned getInBlockPhysRegSize(unsigned int PhysReg, int MBBNo);
  // Cast SrcVal to type DstTy, if the type of SrcVal is different from DstTy.
  // Return the cast instruction upon inserting it at the end of InsertBlock
  Value *castValue(Value *SrcVal, Type *DstTy, BasicBlock *InsertBlock,
                   bool SrcIsSigned = false);

  // Cast SrcVal to type DstTy if the types are different. This function does
  // not change any bits in the value. This allows to interpret SSE register
  // values as floats, doubles or vectors
  // If the passed value is smaller than DstTy, it is extended and padded with
  // 0's. Example:
  // SrcVal = float, DstTy = <4 x i32>
  // Return type: <0x0, 0x0, 0x0, (bitcast SrcVal as i32)>
  // If the passed value is larger than DstTy, the excess bits are truncated.
  // If the types are of the same size, the value is just bitcast
  Value *reinterpretSSERegValue(Value *SrcVal, Type *DstTy,
                                BasicBlock *InsertBlock = nullptr,
                                Instruction *InsertBefore = nullptr);
  // Returns the type of an SSE instruction
  Type *getSSEInstructionType(const MachineInstr &MI,
                              unsigned int SSERegSzInBits, LLVMContext &Ctx);

  // If SrcValue is a ConstantExpr abstraction of rodata index, set metadata of
  // Inst; if SrcValue is an instruction with rodata index metadata, copy it to
  // Inst.
  bool setInstMetadataRODataIndex(Value *SrcValue, Instruction *Inst);
  // Set metadata of the load instruction if it loads from a value abstracting
  // the content of rodata section.
  LoadInst *setInstMetadataRODataContent(LoadInst *Inst);
  // Associate metadata with rodata section start address in the source binary
  bool setGVMetadataRODataInfo(GlobalVariable *, uint64_t RODataSecStart);
  Value *getRelocOffsetForRODataAddress(Value *SrcRODataAddr);

  enum { INVALID_MBB = -1 };

private:
  X86MachineInstructionRaiser *x86MIRaiser;
  // Map of physical registers -> MBBNoToValueMap, representing per-block
  // register definitions.
  PhysRegMBBValueDefMap physRegDefsInMBB;
};


} // end namespace mctoll
} // end namespace llvm

#endif // LVM_TOOLS_LLVM_MCTOLL_X86_X86RAISEDVALUETRACKER_H
