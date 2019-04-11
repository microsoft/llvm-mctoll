//===- DAGBuilder.h ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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

using namespace llvm;

/// DAGBuilder - This is to build DAG for each Function by analyzing
/// MachineInstructions.
class DAGBuilder {
public:
  DAGRaisingInfo &DAGInfo;
  SelectionDAG &DAG;
  /// FuncInfo - Information about the function as a whole.
  FunctionRaisingInfo &FuncInfo;
  DAGBuilder(DAGRaisingInfo &dagInfo, FunctionRaisingInfo &funcInfo)
      : DAGInfo(dagInfo), DAG(dagInfo.getCurDAG()), FuncInfo(funcInfo) {}
  /// visit - Collects the information of each MI to create SDNodes.
  void visit(const MachineInstr &mi);

private:
  /// visitCC - Analyzes CPSR register information of MI to collect conditional
  /// code properties.
  void visitCC(const MachineInstr &mi, MachineSDNode *mnode);
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGBUILDER_H
