//===- DAGBuilder.h ---------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of DAGBuilder class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGBUILDER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGBUILDER_H

#include "DAGRaisingInfo.h"
#include "FunctionRaisingInfo.h"

namespace llvm {
namespace mctoll {

/// This is to build DAG for each Function by analyzing MachineInstructions.
class DAGBuilder {
public:
  DAGRaisingInfo &DAGInfo;
  SelectionDAG &DAG;
  /// FuncInfo - Information about the function as a whole.
  FunctionRaisingInfo &FuncInfo;
  DAGBuilder(DAGRaisingInfo &DagInfo, FunctionRaisingInfo &FuncInfo)
      : DAGInfo(DagInfo), DAG(DagInfo.getCurDAG()), FuncInfo(FuncInfo) {}
  /// visit - Collects the information of each MI to create SDNodes.
  void visit(const MachineInstr &MI);

private:
  /// Analyzes CPSR register information of MI to collect conditional code
  /// properties.
  void visitCC(const MachineInstr &MI, MachineSDNode *MNode);
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGBUILDER_H
