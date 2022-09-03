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

namespace llvm {
namespace mctoll {

class MCInstOrData {
private:
  enum class Tag { DATA, INSTRUCTION };

  union {
    uint32_t Data;
    MCInst Inst;
  };

  Tag Type;

public:
  ~MCInstOrData();
  MCInstOrData &operator=(const MCInstOrData &E);
  MCInstOrData(const MCInstOrData &V);
  MCInstOrData(const MCInst &V);
  MCInstOrData(const uint32_t V);

  uint32_t getData() const { return Data; }
  MCInst getMCInst() const { return Inst; }
  bool isData() const { return (Type == Tag::DATA); }
  bool isMCInst() const { return (Type == Tag::INSTRUCTION); }

  void dump() const;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_MCINSTORDATA_H
