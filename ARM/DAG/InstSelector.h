//===- InstSelector.h -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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

using namespace llvm;

/// InstSelector - Does some selections on the DAG. So far, it just does the
/// instruction selection.
class InstSelector {
public:
  InstSelector(DAGRaisingInfo &dagInfo, FunctionRaisingInfo &funcInfo)
      : DAGInfo(&dagInfo), CurDAG(&dagInfo.getCurDAG()), FuncInfo(&funcInfo) {}
  void select(SDNode *N);

private:
  bool isTwoAddressMode(SDNode *node) {
    if (nullptr == node)
      return false;

    NodePropertyInfo *npi = DAGInfo->NPMap[node];

    if (nullptr == npi)
      return false;

    return npi->IsTwoAddress;
  }
  bool getAddressModule(SDNode *node);
  /// getMDOperand - Gets the Metadata of given SDNode.
  SDValue getMDOperand(SDNode *N);
  /// recordDefinition - Record the new defined Node, it uses to map the
  /// register number to Node. In DAG emitter, emitter get a value of use base
  /// on this defined Node.
  void recordDefinition(SDNode *oldNode, SDNode *newNode);
  /// replaceNode - Replace all uses of F with T, then remove F from the DAG.
  void replaceNode(SDNode *F, SDNode *T);
  /// isArgumentNode - Checks the SDNode is a function argument or not.
  bool isArgumentNode(SDNode *node);
  /// isReturnNode - Checks the SDNode is a function return or not.
  bool isReturnNode(SDNode *node);
  /// selectCode - Instruction opcode selection.
  void selectCode(SDNode *N);
  EVT getDefaultEVT() { return EVT::getEVT(FuncInfo->getDefaultType()); }

  DAGRaisingInfo *DAGInfo;
  SelectionDAG *CurDAG;
  FunctionRaisingInfo *FuncInfo;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_INSTSELECTOR_H
