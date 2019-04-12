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

// This class encapsulates all the necessary bookkeeping and look up of SSA
// values constructed while a MachineFUnction is raised.

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
// Each entry of this map has the following sematics:
// SuperReg is defined in MBBNo using Val and the as a sub-register of size
// PhysReg_Sz. E.g., SuperReg RAX may be actually defined as register of size 16
// (i.e. AX).
using PhysRegMBBValueDefMap = std::map<unsigned int, MBBNoToValueMap>;

class X86RaisedValueTracker {
public:
  X86RaisedValueTracker() = delete;
  X86RaisedValueTracker(X86MachineInstructionRaiser *);
  bool updatePhysRegSSAValue(unsigned int PhysReg, int MBBNo, Value *Val);

  // Return <MBBNo, Value*> pair denoting the defining MBBNo and Value defined
  // for PhysReg.
  std::pair<int, Value *> getInBlockReachingDef(unsigned int PhysReg,
                                                int MBBNo);
  // Return a vector of <MBBNo, Value*> pairs denoting the defining MBB numbers
  // and Values defined for PhysReg in the predecessors of MBBNo.
  std::vector<std::pair<int, Value *>>
  getGlobalReachingDefs(unsigned int PhysReg, int MBBNo);

  Value *getReachingDef(unsigned int PhysReg, int MBBNo);

  Value *getInBlockPhysRegDefVal(unsigned int PhysReg, int MBBNo);
  unsigned getInBlockPhysRegSize(unsigned int PhysReg, int MBBNo);

private:
  X86MachineInstructionRaiser *x86MIRaiser;
  // Map of physical registers -> MBBNoToValueMap, representing per-block
  // register definitions.
  PhysRegMBBValueDefMap physRegDefsInMBB;
};

#endif // LVM_TOOLS_LLVM_MCTOLL_X86_X86RAISEDVALUETRACKER_H
