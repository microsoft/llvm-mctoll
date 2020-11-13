//===- ARMSelectionDAGISel.cpp - Binary raiser utility llvm-mctoll --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMSelectionDAGISel class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMSelectionDAGISel.h"

using namespace llvm;

char ARMSelectionDAGISel::ID = 0;

#define DEBUG_TYPE "mctoll"

ARMSelectionDAGISel::ARMSelectionDAGISel(ARMModuleRaiser &mr)
    : ARMRaiserBase(ID, mr) {}

ARMSelectionDAGISel::~ARMSelectionDAGISel() {
  delete SLT;
  delete SDB;
  delete DAGInfo;
  delete CurDAG;
  delete FuncInfo;
}

void ARMSelectionDAGISel::init(MachineFunction *mf, Function *rf) {
  ARMRaiserBase::init(mf, rf);

  ORE = make_unique<OptimizationRemarkEmitter>(getCRF());
  FuncInfo = new FunctionRaisingInfo();
  CurDAG = new SelectionDAG(*MR->getTargetMachine(), CodeGenOpt::None);
  DAGInfo = new DAGRaisingInfo(*CurDAG);
  SDB = new DAGBuilder(*DAGInfo, *FuncInfo);
  SLT = new InstSelector(*DAGInfo, *FuncInfo);
}

void ARMSelectionDAGISel::selectBasicBlock() {

  for (MachineBasicBlock::const_iterator I = MBB->begin(), E = MBB->end();
       I != E; ++I) {
    SDB->visit(*I);
  }

  doInstructionSelection();
  emitDAG();

  // If the current function has return value, records relationship between
  // BasicBlock and each Value which is mapped with R0. In order to record
  // the return Value of each exit BasicBlock.
  Type *RTy = FuncInfo->Fn->getReturnType();
  if (RTy != nullptr && !RTy->isVoidTy() && MBB->succ_size() == 0) {
    Instruction *TInst = dyn_cast<Instruction>(
        DAGInfo->getRealValue(FuncInfo->RegValMap[ARM::R0]));
    assert(TInst && "A def R0 was pointed to a non-instruction!!!");
    BasicBlock *TBB = TInst->getParent();
    FuncInfo->RetValMap[TBB] = TInst;
  }

  // Free the SelectionDAG state, now that we're finished with it.
  DAGInfo->clear();
  CurDAG->clear();
}

void ARMSelectionDAGISel::doInstructionSelection() {

  SelectionDAG::allnodes_iterator ISelPosition = CurDAG->allnodes_begin();
  while (ISelPosition != CurDAG->allnodes_end()) {
    SDNode *Node = &*ISelPosition++;
    SLT->select(Node);
  }
}

void ARMSelectionDAGISel::emitDAG() {
  IREmitter imt(BB, DAGInfo, FuncInfo);
  imt.setjtList(jtList);
  SelectionDAG::allnodes_iterator ISelPosition = CurDAG->allnodes_begin();
  while (ISelPosition != CurDAG->allnodes_end()) {
    SDNode *Node = &*ISelPosition++;
    imt.emitNode(Node);
  }
}

void ARMSelectionDAGISel::initEntryBasicBlock() {
  BasicBlock *bb = &RF->getEntryBlock();
  for (unsigned i = 0; i < 4; i++) {
    Align MALG(32);
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(RF->getContext()), 0,
                                       nullptr, MALG, "", bb);
    FuncInfo->AllocaMap[i] = Alloc;
    new StoreInst(ConstantInt::getFalse(RF->getContext()), Alloc, bb);
  }
}

bool ARMSelectionDAGISel::doSelection() {
  LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel start.\n");

  MachineFunction &mf = *MF;
  CurDAG->init(mf, *ORE.get(), this, nullptr, nullptr, nullptr, nullptr);
  FuncInfo->set(*MR, *getCRF(), mf, CurDAG);

  initEntryBasicBlock();
  for (MachineBasicBlock &mbb : mf) {
    MBB = &mbb;
    BB = FuncInfo->getOrCreateBasicBlock(MBB);
    selectBasicBlock();
  }

  // Add an additional exit BasicBlock, all of original return BasicBlocks
  // will branch to this exit BasicBlock. This will lead to the function has
  // one and only exit. If the function has return value, this help return
  // R0.
  Function *CurFn = const_cast<Function *>(FuncInfo->Fn);
  BasicBlock *LBB = FuncInfo->getOrCreateBasicBlock();

  if (CurFn->getReturnType()) {
    PHINode *LPHI = PHINode::Create(FuncInfo->getCRF()->getReturnType(),
                                    FuncInfo->RetValMap.size(), "", LBB);
    for (auto Pair : FuncInfo->RetValMap)
      LPHI->addIncoming(Pair.second, Pair.first);

    ReturnInst::Create(CurFn->getContext(), LPHI, LBB);
  } else
    ReturnInst::Create(CurFn->getContext(), LBB);

  for (auto &FBB : CurFn->getBasicBlockList())
    if (FBB.getTerminator() == nullptr)
      BranchInst::Create(LBB, &FBB);

  FuncInfo->clear();

  LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel end.\n");

  return true;
}

bool ARMSelectionDAGISel::setjtList(std::vector<JumpTableInfo> &List) {
  jtList = List;
  return true;
}

bool ARMSelectionDAGISel::runOnMachineFunction(MachineFunction &mf) {
  bool rtn = false;
  init();
  rtn = doSelection();
  return rtn;
}
#undef DEBUG_TYPE

#ifdef __cplusplus
extern "C" {
#endif

FunctionPass *InitializeARMSelectionDAGISel(ARMModuleRaiser &mr) {
  return new ARMSelectionDAGISel(mr);
}

#ifdef __cplusplus
}
#endif
