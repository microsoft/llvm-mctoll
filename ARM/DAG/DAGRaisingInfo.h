//===- DAGRaisingInfo.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of DAGRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGRAISERINGINFO_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGRAISERINGINFO_H

#include "ModuleRaiser.h"
#include "SelectionCommon.h"
#include "llvm/ADT/DenseMap.h"

/// DAGRaisingInfo - This is a extention of SelectionDAG. It contains
/// additional information of DAG which is used by llvm-mctoll.
class DAGRaisingInfo {
public:
  DAGRaisingInfo() = delete;
  DAGRaisingInfo(SelectionDAG &dag);
  void clear();
  /// getCurDAG - Gets corresponding SelectionDAG object.
  SelectionDAG &getCurDAG() { return DAG; }
  /// getRealValue - Gets the related IR Value of given SDNode.
  Value *getRealValue(SDNode *Node);
  /// setRealValue - Set the related IR Value to SDNode.
  void setRealValue(SDNode *N, Value *V);

  SelectionDAG &DAG;
  /// NPMap - The map for each SDNode with its additional preperty.
  DenseMap<SDNode *, NodePropertyInfo *> NPMap;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_DAG_DAGRAISERINGINFO_H
