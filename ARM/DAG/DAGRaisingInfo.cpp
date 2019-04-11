//===- DAGRaisingInfo.cpp - Binary raiser utility llvm-mctoll -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementaion of DAGRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "DAGRaisingInfo.h"

using namespace llvm;

DAGRaisingInfo::DAGRaisingInfo(SelectionDAG &dag) : DAG(dag) {}

/// getRealValue - Gets the related IR Value of given SDNode.
Value *DAGRaisingInfo::getRealValue(SDNode *Node) {
  assert(Node != nullptr && "Node cannot be nullptr!");
  assert(NPMap[Node] != nullptr &&
         "Cannot find the corresponding node proprety!");
  return NPMap[Node]->Val;
}

/// setRealValue - Set the related IR Value to SDNode.
void DAGRaisingInfo::setRealValue(SDNode *N, Value *V) {
  if (NPMap.count(N) == 0)
    NPMap[N] = new NodePropertyInfo();

  NPMap[N]->Val = V;
}

void DAGRaisingInfo::clear() {
  for (auto &elmt : NPMap)
    delete elmt.second;

  NPMap.clear();
}
