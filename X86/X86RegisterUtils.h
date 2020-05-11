//==-- X86RegisterUtils.h - Binary raiser utility llvm-mctoll ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the various constants and static functions used for
// raising x86 binaries in llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef TOOLS_LLVM_MCTOLL_X86_X86RAISERUTILS_H_
#define TOOLS_LLVM_MCTOLL_X86_X86RAISERUTILS_H_

#include "X86InstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include <string>
#include <vector>

using namespace std;
using namespace llvm;

namespace X86RegisterUtils {
// Separate flags - EFLAGS
// Note : only those that are currently used are represented here.
// EFLAGS are considered no different from GPRs
namespace EFLAGS {
enum {
  CF = X86::NUM_TARGET_REGS + 1,
  PF = X86::NUM_TARGET_REGS + 2,
  AF = X86::NUM_TARGET_REGS + 3,
  ZF = X86::NUM_TARGET_REGS + 4,
  SF = X86::NUM_TARGET_REGS + 5,
  OF = X86::NUM_TARGET_REGS + 6,
  UNDEFINED = X86::NUM_TARGET_REGS + 7

};
} // namespace EFLAGS
using EFLAGBit = uint16_t;

extern const vector<MCPhysReg> GPR64ArgRegs64Bit;

extern const vector<MCPhysReg> GPR64ArgRegs32Bit;

extern const vector<MCPhysReg> GPR64ArgRegs16Bit;

extern const vector<MCPhysReg> GPR64ArgRegs8Bit;

// static const ArrayRef<MCPhysReg> GPR64ArgRegsWin64({X86::RCX, X86::RDX,
// X86::R8,
//                                                    X86::R9});
extern const vector<EFLAGBit> EFlagBits;

bool isEflagBit(unsigned RegNo);
int getEflagBitIndex(unsigned EFBit);
string getEflagName(unsigned EFBit);
bool is64BitPhysReg(unsigned int PReg);
bool is32BitPhysReg(unsigned int PReg);
bool is16BitPhysReg(unsigned int PReg);
bool is8BitPhysReg(unsigned int PReg);
bool is32BitSSE2Reg(unsigned int PReg);
bool is64BitSSE2Reg(unsigned int PReg);
bool isGPReg(unsigned int PReg);
bool isSSE2Reg(unsigned int PReg);
unsigned getPhysRegSizeInBits(unsigned int PReg);
unsigned getArgumentReg(int Index, Type *Ty);
} // namespace X86RegisterUtils
#endif /* TOOLS_LLVM_MCTOLL_X86_X86RAISERUTILS_H_ */
