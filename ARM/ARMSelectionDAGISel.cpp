//===- ARMSelectionDAGISel.cpp - Binary raiser utility llvm-mctoll --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
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
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(RF->getContext()), 0,
                                       nullptr, 4, "", bb);
    FuncInfo->AllocaMap[i] = Alloc;
    new StoreInst(ConstantInt::getFalse(RF->getContext()), Alloc, bb);
  }
}

bool ARMSelectionDAGISel::doSelection() {
  if (PrintPass)
    dbgs() << "ARMSelectionDAGISel start.\n";

  MachineFunction &mf = *MF;
  CurDAG->init(mf, *ORE.get(), this, nullptr, nullptr);
  FuncInfo->set(*MR, *getCRF(), mf, CurDAG);

  initEntryBasicBlock();
  for (MachineBasicBlock &mbb : mf) {
    MBB = &mbb;
    BB = FuncInfo->getOrCreateBasicBlock(MBB);
    selectBasicBlock();
  }

  FuncInfo->clear();

  if (PrintPass)
    dbgs() << "ARMSelectionDAGISel end.\n";

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

#ifdef __cplusplus
extern "C" {
#endif

FunctionPass *InitializeARMSelectionDAGISel(ARMModuleRaiser &mr) {
  return new ARMSelectionDAGISel(mr);
}

#ifdef __cplusplus
}
#endif
