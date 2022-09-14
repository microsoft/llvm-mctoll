//===- InstSelector.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of InstSelector class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_INSTSELECTOR_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_INSTSELECTOR_H

#include "DAGRaisingInfo.h"
#include "FunctionRaisingInfo.h"

namespace llvm {
namespace mctoll {

/// Does some selections on the DAG. So far, it just does the instruction
/// selection.
class InstSelector {
public:
  InstSelector(DAGRaisingInfo &DagInfoVal, FunctionRaisingInfo &FuncInfoVal)
      : DAGInfo(&DagInfoVal), CurDAG(&DagInfoVal.getCurDAG()), FuncInfo(&FuncInfoVal) {}
  void select(SDNode *N);

private:
  bool isTwoAddressMode(SDNode *Node) {
    if (nullptr == Node)
      return false;

    NodePropertyInfo *NPI = DAGInfo->NPMap[Node];

    if (nullptr == NPI)
      return false;

    return NPI->IsTwoAddress;
  }
  // bool getAddressModule(SDNode *Node);
  /// Gets the Metadata of given SDNode.
  SDValue getMDOperand(SDNode *N);
  /// Record the new defined Node, it uses to map the register number to Node.
  /// In DAG emitter, emitter get a value of use base on this defined Node.
  void recordDefinition(SDNode *OldNode, SDNode *NewNode);
  /// Replace all uses of F with T, then remove F from the DAG.
  void replaceNode(SDNode *F, SDNode *T);
  /// Checks the SDNode is a function argument or not.
  bool isArgumentNode(SDNode *Node);
  /// Checks the SDNode is a function return or not.
  bool isReturnNode(SDNode *Node);
  /// Instruction opcode selection.
  void selectCode(SDNode *N);
  EVT getDefaultEVT() { return EVT::getEVT(FuncInfo->getDefaultType()); }

  DAGRaisingInfo *DAGInfo;
  SelectionDAG *CurDAG;
  FunctionRaisingInfo *FuncInfo;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_INSTSELECTOR_H
