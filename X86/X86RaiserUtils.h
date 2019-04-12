//===-- X86RaiserUtils.h ----------------------------------------*- C++ -*-===//
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

#include "llvm/MC/MCRegisterInfo.h"

// Unfortunately, tablegen does not have an interface to query
// information about argument registers used for calling
// convention used.
static const std::vector<MCPhysReg> GPR64ArgRegs64Bit({X86::RDI, X86::RSI,
                                                       X86::RDX, X86::RCX,
                                                       X86::R8, X86::R9});

static const std::vector<MCPhysReg> GPR64ArgRegs32Bit({X86::EDI, X86::ESI,
                                                       X86::EDX, X86::ECX,
                                                       X86::R8D, X86::R9D});

static const std::vector<MCPhysReg>
    GPR64ArgRegs16Bit({X86::DI, X86::SI, X86::DX, X86::CX, X86::R8W, X86::R9W});

static const std::vector<MCPhysReg> GPR64ArgRegs8Bit({X86::DIL, X86::SIL,
                                                      X86::DL, X86::CL,
                                                      X86::R8B, X86::R9B});

// static const ArrayRef<MCPhysReg> GPR64ArgRegsWin64({X86::RCX, X86::RDX,
// X86::R8,
//                                                    X86::R9});

static inline bool is64BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR64RegClassID].contains(PReg);
}

static bool inline is32BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR32RegClassID].contains(PReg);
}

static bool inline is16BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR16RegClassID].contains(PReg);
}

static bool inline is8BitPhysReg(unsigned int PReg) {
  return X86MCRegisterClasses[X86::GR8RegClassID].contains(PReg);
}

#endif /* TOOLS_LLVM_MCTOLL_X86_X86RAISERUTILS_H_ */
