//===- SelectionCommon.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains some declarations, and defines some structures, which are
// use to DAG.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_SELECTIONCOMMON_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_SELECTIONCOMMON_H

#include "ARMISelLowering.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"

/// This is the start index of EXT_ARMISD. Because node types which start
/// from ARMISD::VLD1DUP (Next to ARMISD::MEMCPY) are identified as
/// TARGET_MEMORY_OPCODE, we set EXTARMISD_OP_BEGIN index after ARMISD::MEMCPY,
/// plugs 40 to keep long time with no confliction.
#define EXTARMISD_OP_BEGIN (ARMISD::MEMCPY + 40)

namespace llvm {
namespace EXT_ARMISD {

enum NodeType {
  BX_RET = EXTARMISD_OP_BEGIN,
  BRD, // Direct branch
  LOAD,
  STORE,
  MSR,
  MRS,
  RSB,
  RSC,
  SBC,
  TEQ,
  TST,
  BIC,
  MLA,
  UXTB,

  EXT_ARMISD_OP_END
};

} // namespace EXT_ARMISD
} // namespace llvm

using namespace llvm;

/// This structure is to extend SDNode properties, some additional SDNode
/// properties which are used by llvm-mctoll will be kept at here.
typedef struct NodeProperty {
  bool HasCPSR;
  bool Special;
  bool UpdateCPSR;
  unsigned Cond;
  bool IsTwoAddress;
  Value *Val;
  const MachineInstr *MI;
} NodePropertyInfo;

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_SELECTIONCOMMON_H
