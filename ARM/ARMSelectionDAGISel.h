//===- ARMSelectionDAGISel.h ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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

/// ARMSelectionDAGISel - This is responsible for constructing DAG, and does
/// instruction selection on the DAG, eventually emits SDNodes of the DAG to
/// LLVM IRs.
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
  IREmitter *IMT;

  SelectionDAG *CurDAG;
  DAGRaisingInfo *DAGInfo;
  MachineBasicBlock *MBB;
  BasicBlock *BB;
  std::vector<JumpTableInfo> jtList;
};

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMSELECTIONDAGISEL_H
