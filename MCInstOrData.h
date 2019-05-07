//===-- MCInstOrData.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MCINSTORDATA_H
#define LLVM_TOOLS_LLVM_MCTOLL_MCINSTORDATA_H

#include "llvm/MC/MCInst.h"

using namespace llvm;

class MCInstOrData {
private:
  enum class Tag { DATA, INSTRUCTION };

  union {
    uint32_t d;
    MCInst i;
  };

  Tag type;

public:
  ~MCInstOrData();
  MCInstOrData &operator=(const MCInstOrData &);
  MCInstOrData(const MCInstOrData &);
  MCInstOrData(const MCInst &);
  MCInstOrData(const uint32_t);
  MCInst get_mcInst() const;
  uint32_t get_data() const;
  bool is_data() const { return (type == Tag::DATA); }
  bool is_mcInst() const { return (type == Tag::INSTRUCTION); }
  void dump() const;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_MCINSTRAISER_H
