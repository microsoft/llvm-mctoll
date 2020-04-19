//===-- RISCV32ModuleRaiser.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of RISCV32ModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_RISCV_CALLING_CONVENTION_H
#define LLVM_TOOLS_LLVM_MCTOLL_RISCV_CALLING_CONVENTION_H

#include <vector>
#include "MCTargetDesc/RISCVMCTargetDesc.h"
#include "llvm/MC/MCRegisterInfo.h"

using namespace llvm;
using std::vector;

class RISCVCallingConvention {
public:
  typedef typename vector<MCPhysReg>::iterator RandomAccessIterator;
  typedef typename vector<MCPhysReg>::const_iterator ConstRandomAccessIterator;

public:
  RISCVCallingConvention() : mIntArgRegs(), mFloatArgRegs()
  {}
  virtual ~RISCVCallingConvention()
  {}
  
  virtual unsigned int intRegLength() const = 0;
  virtual unsigned int floatRegLength() const = 0;
  virtual unsigned int numIntRegArgs() const = 0;
  virtual unsigned int numFloatRegArgs() const = 0;
  virtual bool isSoftFloat() const = 0;

  RISCVCallingConvention::RandomAccessIterator intArgRegsBegin() { return mIntArgRegs.begin(); }
  RISCVCallingConvention::ConstRandomAccessIterator intArgRegsBegin() const { return mIntArgRegs.begin(); }
  RISCVCallingConvention::RandomAccessIterator intArgRegsEnd() { return mIntArgRegs.end(); }
  RISCVCallingConvention::ConstRandomAccessIterator intArgRegsEnd() const { return mIntArgRegs.end(); }

  RISCVCallingConvention::RandomAccessIterator floatArgRegsBegin() { return mFloatArgRegs.begin(); }
  RISCVCallingConvention::ConstRandomAccessIterator floatArgRegsBegin() const { return mFloatArgRegs.begin(); }
  RISCVCallingConvention::RandomAccessIterator floatArgRegsEnd() { return mFloatArgRegs.end(); }
  RISCVCallingConvention::ConstRandomAccessIterator floatArgRegsEnd() const { return mFloatArgRegs.end(); }

protected:
  void addIntArgRegister(MCPhysReg reg) { mIntArgRegs.emplace_back(reg); }
  void addFloatArgRegister(MCPhysReg reg) { mFloatArgRegs.emplace_back(reg); }
  virtual void addIntRegs8() = 0;
  virtual void addFloatRegsSingle() = 0;
  virtual void addFloatRegsDouble() = 0;

private:
  vector<MCPhysReg> mIntArgRegs;
  vector<MCPhysReg> mFloatArgRegs;
};

class RISCVCallingConventionI32 : public RISCVCallingConvention {
public:
  RISCVCallingConventionI32() : RISCVCallingConvention() {}
  virtual ~RISCVCallingConventionI32()
  {}
  
  unsigned int intRegLength() const { return 32; }
};

class RISCVCallingConventionI64 : public RISCVCallingConvention {
public:
  RISCVCallingConventionI64() : RISCVCallingConvention() {}
  virtual ~RISCVCallingConventionI64()
  {}
  
  unsigned int intRegLength() const { return 64; }
  unsigned int numIntRegArgs() const { return 8; }
};

class RISCVILP32 : public RISCVCallingConventionI32 {
public:
  RISCVILP32();
  virtual ~RISCVILP32()
  {}
  
  unsigned int floatRegLength() const { return 0; }
  unsigned int numIntRegArgs() const { return 8; }
  unsigned int numFloatRegArgs() const { return 0; }
  bool isSoftFloat() const { return true; }
};

class RISCVILP32F : public RISCVCallingConventionI32 {
public:
  RISCVILP32F();
  virtual ~RISCVILP32F()
  {}
  
  unsigned int floatRegLength() const { return 32; }
  unsigned int numIntRegArgs() const { return 8; }
  unsigned int numFloatRegArgs() const { return 8; }
  bool isSoftFloat() const { return false; }
};

class RISCVILP32D : public RISCVCallingConventionI32 {
public:
  RISCVILP32D();
  virtual ~RISCVILP32D()
  {}
  
  unsigned int floatRegLength() const { return 64; }
  unsigned int numIntRegArgs() const { return 8; }
  unsigned int numFloatRegArgs() const { return 8; }
  bool isSoftFloat() const { return false; }
};

class RISCVILP32E : public RISCVCallingConventionI32 {
public:
  RISCVILP32E();
  virtual ~RISCVILP32E()
  {}
  
  unsigned int floatRegLength() const { return 0; }
  unsigned int numIntRegArgs() const { return 6; }
  unsigned int numFloatRegArgs() const { return 0; }
  bool isSoftFloat() const { return true; }
};

class RISCVLP64 : public RISCVCallingConventionI64 {
public:
  RISCVLP64();
  virtual ~RISCVLP64()
  {}
  
  unsigned int floatRegLength() const { return 0; }
  unsigned int numFloatRegArgs() const { return 0; }
  bool isSoftFloat() const { return true; }
};

class RISCVLP64F : public RISCVCallingConventionI64 {
public:
  RISCVLP64F();
  virtual ~RISCVLP64F()
  {}
  
  unsigned int floatRegLength() const { return 32; }
  unsigned int numFloatRegArgs() const { return 8; }
  bool isSoftFloat() const { return false; }
};

class RISCVLP64D : public RISCVCallingConventionI64 {
public:
  RISCVLP64D();
  virtual ~RISCVLP64D()
  {}
  
  unsigned int floatRegLength() const { return 64; }
  unsigned int numFloatRegArgs() const { return 8; }
  bool isSoftFloat() const { return false; }
};
  
#endif // LLVM_TOOLS_LLVM_MCTOLL_RISCV_CALLING_CONVENTION_H
