//===-- MCInstOrData.cpp ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCInstOrData.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm::mctoll;

MCInstOrData::MCInstOrData(const MCInstOrData &V) {
  Type = V.Type;
  switch (Type) {
  case Tag::DATA:
    Data = V.Data;
    break;
  case Tag::INSTRUCTION:
    new (&Inst) MCInst(V.Inst);
    break;
  }
}

MCInstOrData::MCInstOrData(const MCInst &V) {
  Type = Tag::INSTRUCTION;
  new (&Inst) MCInst(V); // placement new: explicitly construct MCInst
}

MCInstOrData::MCInstOrData(const uint32_t V) {
  Type = Tag::DATA;
  Data = V;
}

// This is needed because of user-defined variant MCInst being part of MCInst
MCInstOrData &MCInstOrData::operator=(const MCInstOrData &E) {
  if (Type == Tag::INSTRUCTION) {
    if (E.Type == Tag::INSTRUCTION) {
      // Usual MCInst assignment
      Inst = E.Inst;
      return *this;
    }
    // Explicit destroy
    Inst.~MCInst();
  }

  switch (E.Type) {
  case Tag::DATA:
    Data = E.Data;
    break;
  case Tag::INSTRUCTION:
    new (&Inst) MCInst(E.Inst);
    Type = E.Type;
    break;
  }
  return *this;
}

void MCInstOrData::dump(const MCInstPrinter *Printer,
                        StringRef Separator,
                        const MCRegisterInfo *RegInfo) const {
  switch (Type) {
  case Tag::DATA:
    dbgs() << "0x" << format("%04" PRIx16, Data) << "\n";
    break;
  case Tag::INSTRUCTION:
    LLVM_DEBUG(Inst.dump_pretty(dbgs(), Printer, Separator, RegInfo));
    dbgs() << "\n";
    break;
  }
}

MCInstOrData::~MCInstOrData() {
  if (Type == Tag::INSTRUCTION)
    Inst.~MCInst(); // explicit destroy
}

#undef DEBUG_TYPE
