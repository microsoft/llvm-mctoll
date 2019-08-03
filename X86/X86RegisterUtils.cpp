//==-- X86RaiserUtils.cpp - Binary raiser utility llvm-mctoll -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of X86RegisterUtils namespace for use
// by llvm-mctoll. This encapsulates utilities related to X86 registers and
// EFLAGS that are not available in core LLVM.
//
//===----------------------------------------------------------------------===//

#include "X86RegisterUtils.h"

namespace X86RegisterUtils {
// Unfortunately, tablegen does not have an interface to query
// information about argument registers used for calling
// convention used.
const vector<MCPhysReg> GPR64ArgRegs64Bit({X86::RDI, X86::RSI, X86::RDX,
                                           X86::RCX, X86::R8, X86::R9});

const vector<MCPhysReg> GPR64ArgRegs32Bit({X86::EDI, X86::ESI, X86::EDX,
                                           X86::ECX, X86::R8D, X86::R9D});

const vector<MCPhysReg> GPR64ArgRegs16Bit({X86::DI, X86::SI, X86::DX, X86::CX,
                                           X86::R8W, X86::R9W});

const vector<MCPhysReg> GPR64ArgRegs8Bit({X86::DIL, X86::SIL, X86::DL, X86::CL,
                                          X86::R8B, X86::R9B});

// static const ArrayRef<MCPhysReg> GPR64ArgRegsWin64({X86::RCX, X86::RDX,
// X86::R8,
//                                                    X86::R9});
const vector<EFLAGBit> EFlagBits({EFLAGS::CF, EFLAGS::PF, EFLAGS::AF,
                                  EFLAGS::ZF, EFLAGS::SF, EFLAGS::OF});

bool isEflagBit(unsigned RegNo) {
  return ((RegNo >= EFLAGS::CF) && (RegNo < EFLAGS::UNDEFINED));
}

int getEflagBitIndex(unsigned EFBit) {
  assert(isEflagBit(EFBit) && "Undefined EFLAGS bit");
  int index = 0;
  for (auto v : EFlagBits) {
    if (v == EFBit)
      return index;
    else
      index++;
  }
  assert(false && "Unknown EFLAGS bit");
  return -1;
}

string getEflagName(unsigned EFBit) {
  switch (EFBit) {
  case EFLAGS::CF:
    return "CF";
    break;
  case EFLAGS::PF:
    return "PF";
    break;
  case EFLAGS::AF:
    return "AF";
    break;
  case EFLAGS::ZF:
    return "ZF";
    break;
  case EFLAGS::SF:
    return "SF";
    break;
  case EFLAGS::OF:
    return "OF";
    break;
  default:
    assert(false && "Unknown EFLAGS bit");
  }
  return "";
}

bool is64BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR64RegClassID].contains(PReg);
}

bool is32BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR32RegClassID].contains(PReg);
}

bool is16BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR16RegClassID].contains(PReg);
}

bool is8BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR8RegClassID].contains(PReg);
}

unsigned int getPhysRegSizeInBits(unsigned int PReg) {
  if (is64BitPhysReg(PReg))
    return 64;
  else if (is32BitPhysReg(PReg))
    return 32;
  else if (is16BitPhysReg(PReg))
    return 16;
  else if (is8BitPhysReg(PReg))
    return 8;
  else
    assert(false && "Unhandled physical register specified");
  return 0;
}
} // namespace X86RegisterUtils
