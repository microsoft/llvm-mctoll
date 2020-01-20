//===- ARMSelectionDAGISel.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMSelectionDAGISel class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMSELECTIONDAGISEL_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMSELECTIONDAGISEL_H

#include "ARMRaiserBase.h"
#include "DAGBuilder.h"
#include "DAGRaisingInfo.h"
#include "FunctionRaisingInfo.h"
#include "IREmitter.h"
#include "InstSelector.h"
#include "ModuleRaiser.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"

/// This is responsible for constructing DAG, and does instruction selection on
/// the DAG, eventually emits SDNodes of the DAG to LLVM IRs.
class ARMSelectionDAGISel : public ARMRaiserBase {
public:
  ARMSelectionDAGISel(ARMModuleRaiser &mr);
  ~ARMSelectionDAGISel() override;
  void init(MachineFunction *mf = nullptr, Function *rf = nullptr) override;
  bool doSelection();
  bool runOnMachineFunction(MachineFunction &mf) override;
  bool setjtList(std::vector<JumpTableInfo> &List);
  static char ID;

private:
  void initEntryBasicBlock();
  void selectBasicBlock();
  void doInstructionSelection();
  void emitDAG();

  std::unique_ptr<OptimizationRemarkEmitter> ORE;

  FunctionRaisingInfo *FuncInfo;
  DAGBuilder *SDB;
  InstSelector *SLT;

  SelectionDAG *CurDAG;
  DAGRaisingInfo *DAGInfo;
  MachineBasicBlock *MBB;
  BasicBlock *BB;
  std::vector<JumpTableInfo> jtList;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMSELECTIONDAGISEL_H
