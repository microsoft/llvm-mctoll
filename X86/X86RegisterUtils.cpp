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

using namespace llvm;
using namespace llvm::mctoll;
using namespace llvm::mctoll::X86RegisterUtils;

// Unfortunately, tablegen does not have an interface to query
// information about argument registers used for calling
// convention used.
const vector<MCPhysReg> X86RegisterUtils::GPR64ArgRegs64Bit({X86::RDI, X86::RSI, X86::RDX,
                                           X86::RCX, X86::R8, X86::R9});

const vector<MCPhysReg> X86RegisterUtils::GPR64ArgRegs32Bit({X86::EDI, X86::ESI, X86::EDX,
                                           X86::ECX, X86::R8D, X86::R9D});

const vector<MCPhysReg> X86RegisterUtils::GPR64ArgRegs16Bit({X86::DI, X86::SI, X86::DX, X86::CX,
                                           X86::R8W, X86::R9W});

const vector<MCPhysReg> X86RegisterUtils::GPR64ArgRegs8Bit({X86::DIL, X86::SIL, X86::DL, X86::CL,
                                          X86::R8B, X86::R9B});

const vector<MCPhysReg> X86RegisterUtils::SSEArgRegs64Bit({X86::XMM0, X86::XMM1,
                                          X86::XMM2, X86::XMM3,
                                          X86::XMM4, X86::XMM5,
                                          X86::XMM6, X86::XMM7});

// static const ArrayRef<MCPhysReg> GPR64ArgRegsWin64({X86::RCX, X86::RDX,
// X86::R8,
//                                                    X86::R9});
const vector<EFLAGBit> X86RegisterUtils::EFlagBits({EFLAGS::CF, EFLAGS::PF, EFLAGS::AF,
                                  EFLAGS::ZF, EFLAGS::SF, EFLAGS::OF});

bool X86RegisterUtils::isEflagBit(unsigned RegNo) {
  return ((RegNo >= EFLAGS::CF) && (RegNo < EFLAGS::UNDEFINED));
}

int X86RegisterUtils::getEflagBitIndex(unsigned EFBit) {
  assert(isEflagBit(EFBit) && "Undefined EFLAGS bit");
  int index = 0;
  for (auto v : X86RegisterUtils::EFlagBits) {
    if (v == EFBit)
      return index;
    else
      index++;
  }
  assert(false && "Unknown EFLAGS bit");
  return -1;
}

string X86RegisterUtils::getEflagName(unsigned EFBit) {
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

bool X86RegisterUtils::is32BitSSE2Reg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::FR32RegClassID].contains(PReg);
}

bool X86RegisterUtils::is64BitSSE2Reg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::FR64RegClassID].contains(PReg);
}

bool X86RegisterUtils::is64BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR64RegClassID].contains(PReg);
}

bool X86RegisterUtils::is32BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR32RegClassID].contains(PReg);
}

bool X86RegisterUtils::is16BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR16RegClassID].contains(PReg);
}

bool X86RegisterUtils::is8BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR8RegClassID].contains(PReg);
}

unsigned int X86RegisterUtils::getPhysRegSizeInBits(unsigned int PReg) {
  if (X86RegisterUtils::is64BitPhysReg(PReg) || X86RegisterUtils::is64BitSSE2Reg(PReg))
    return 64;
  else if (X86RegisterUtils::is32BitPhysReg(PReg) || X86RegisterUtils::is32BitSSE2Reg(PReg))
    return 32;
  else if (X86RegisterUtils::is16BitPhysReg(PReg))
    return 16;
  else if (X86RegisterUtils::is8BitPhysReg(PReg))
    return 8;
  else if (isEflagBit(PReg))
    return 1;

  llvm_unreachable("Unhandled physical register specified");
}

bool X86RegisterUtils::isSSE2Reg(unsigned int PReg) {
  return (X86RegisterUtils::is32BitSSE2Reg(PReg) || X86RegisterUtils::is64BitSSE2Reg(PReg));
}

bool X86RegisterUtils::isGPReg(unsigned int PReg) {
  return (X86RegisterUtils::is8BitPhysReg(PReg) || X86RegisterUtils::is16BitPhysReg(PReg) || X86RegisterUtils::is32BitPhysReg(PReg) ||
          X86RegisterUtils::is64BitPhysReg(PReg));
}

unsigned X86RegisterUtils::getArgumentReg(int Index, Type *Ty) {
  llvm::LLVMContext &Ctx(Ty->getContext());

  // Note: any pointer is an address and hence uses a 64-bit register
  if ((Ty == Type::getInt64Ty(Ctx)) || (Ty->isPointerTy())) {
    return X86RegisterUtils::GPR64ArgRegs64Bit[Index];
  } else if (Ty == Type::getInt32Ty(Ctx)) {
    return X86RegisterUtils::GPR64ArgRegs32Bit[Index];
  } else if (Ty == Type::getInt16Ty(Ctx)) {
    return X86RegisterUtils::GPR64ArgRegs16Bit[Index];
  } else if (Ty == Type::getInt8Ty(Ctx)) {
    return X86RegisterUtils::GPR64ArgRegs8Bit[Index];
  }
  return 0;
}

//} // end namespace X86RegisterUtils
