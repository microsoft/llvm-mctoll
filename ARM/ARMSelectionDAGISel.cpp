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
using namespace llvm::mctoll;

char ARMSelectionDAGISel::ID = 0;

#define DEBUG_TYPE "mctoll"

ARMSelectionDAGISel::ARMSelectionDAGISel(ARMModuleRaiser &CurrMR,
                                         MachineFunction *CurrMF,
                                         Function *CurrRF)
    : ARMRaiserBase(ID, CurrMR) {
  MF = CurrMF;
  RF = CurrRF;
  ORE = make_unique<OptimizationRemarkEmitter>(getRaisedFunction());
  FuncInfo = new FunctionRaisingInfo();
  CurDAG = new SelectionDAG(*MR->getTargetMachine(), CodeGenOpt::None);
  DAGInfo = new DAGRaisingInfo(*CurDAG);
  SDB = new DAGBuilder(*DAGInfo, *FuncInfo);
  SLT = new InstSelector(*DAGInfo, *FuncInfo);
}

ARMSelectionDAGISel::~ARMSelectionDAGISel() {
  delete SLT;
  delete SDB;
  delete DAGInfo;
  delete CurDAG;
  delete FuncInfo;
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
  imt.setjtList(JTList);
  SelectionDAG::allnodes_iterator ISelPosition = CurDAG->allnodes_begin();
  while (ISelPosition != CurDAG->allnodes_end()) {
    SDNode *Node = &*ISelPosition++;
    imt.emitNode(Node);
  }
}

void ARMSelectionDAGISel::initEntryBasicBlock() {
  BasicBlock *BB = &RF->getEntryBlock();
  for (unsigned i = 0; i < 4; i++) {
    Align MALG(32);
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(RF->getContext()), 0,
                                       nullptr, MALG, "", BB);
    FuncInfo->AllocaMap[i] = Alloc;
    new StoreInst(ConstantInt::getFalse(RF->getContext()), Alloc, BB);
  }
}

bool ARMSelectionDAGISel::doSelection() {
  LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel start.\n");

  //MachineFunction &mf = *MF;
  CurDAG->init(*MF, *ORE.get(), this, nullptr, nullptr, nullptr, nullptr);
  FuncInfo->set(*MR, *getRaisedFunction(), *MF, CurDAG);

  initEntryBasicBlock();
  for (MachineBasicBlock &Block : *MF) {
    MBB = &Block;
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
  JTList = List;
  return true;
}

bool ARMSelectionDAGISel::runOnMachineFunction(MachineFunction &MF) {
  init();
  return doSelection();
}

extern "C" FunctionPass *createARMSelectionDAGISel(ARMModuleRaiser &MR,
                                                   MachineFunction *MF,
                                                   Function *RF) {
  return new ARMSelectionDAGISel(MR, MF, RF);
}
