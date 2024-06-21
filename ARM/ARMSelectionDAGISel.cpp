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
  LLVM_DEBUG(dumpDAG());
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
  IREmitter Imt(BB, DAGInfo, FuncInfo);
  Imt.setjtList(JTList);
  SelectionDAG::allnodes_iterator ISelPosition = CurDAG->allnodes_begin();
  while (ISelPosition != CurDAG->allnodes_end()) {
    SDNode *Node = &*ISelPosition++;
    Imt.emitNode(Node);
  }
}

void ARMSelectionDAGISel::initEntryBasicBlock() {
  BasicBlock *EntryBlock = &RF->getEntryBlock();
  for (unsigned Idx = 0; Idx < 4; Idx++) {
    Align MALG(32);
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(RF->getContext()), 0,
                                       nullptr, MALG, "", EntryBlock);
    FuncInfo->AllocaMap[Idx] = Alloc;
    new StoreInst(ConstantInt::getFalse(RF->getContext()), Alloc, EntryBlock);
  }
}

bool ARMSelectionDAGISel::doSelection() {
  LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel start.\n");

  //MachineFunction &mf = *MF;
  CurDAG->init(*MF, *ORE.get(), this, nullptr, nullptr, nullptr, nullptr, nullptr);
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

  for (auto &FBB : *CurFn)
    if (FBB.getTerminator() == nullptr)
      BranchInst::Create(LBB, &FBB);

  FuncInfo->clear();

  // For debugging.
  LLVM_DEBUG(MF->dump());
  LLVM_DEBUG(getRaisedFunction()->dump());
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


// Modified version SelectionDAG::dump() for support EXT_ARMISD::NodeType
// based on llvm/lib/CodeGen/SelectionDAG/SelectionDAGDumper.cpp

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
std::string getOperationName(const SelectionDAG *DAG, const SDNode *Node) {
#define MAKE_CASE(V)                                                           \
  case V:                                                                      \
    return #V;
  switch ((EXT_ARMISD::NodeType)Node->getOpcode()) {
    MAKE_CASE(EXT_ARMISD::BX_RET)
    MAKE_CASE(EXT_ARMISD::BRD)
    MAKE_CASE(EXT_ARMISD::LOAD)
    MAKE_CASE(EXT_ARMISD::STORE)
    MAKE_CASE(EXT_ARMISD::MSR)
    MAKE_CASE(EXT_ARMISD::MRS)
    MAKE_CASE(EXT_ARMISD::RSB)
    MAKE_CASE(EXT_ARMISD::RSC)
    MAKE_CASE(EXT_ARMISD::SBC)
    MAKE_CASE(EXT_ARMISD::TEQ)
    MAKE_CASE(EXT_ARMISD::TST)
    MAKE_CASE(EXT_ARMISD::BIC)
    MAKE_CASE(EXT_ARMISD::MLA)
    MAKE_CASE(EXT_ARMISD::UXTB)
  default:
    std::string Name = Node->getOperationName(DAG);
    if (!Name.empty()) return Name;
    return "<<Unknown Target Node #" + utostr(Node->getOpcode()) + ">>";
  }
}

void printTypes(const SDNode *Node) {
  for (unsigned Idx = 0, E = Node->getNumValues(); Idx != E; ++Idx) {
    if (Idx) dbgs() << ",";
    if (Node->getValueType(Idx) == MVT::Other)
      dbgs() << "ch";
    else
      dbgs() << Node->getValueType(Idx).getEVTString();
  }
}

/// Return true if this node is so simple that we should just print it inline
/// if it appears as an operand.
static bool shouldPrintInline(const SDNode &Node) {
  if (Node.getOpcode() == ISD::EntryToken)
    return false;
  return Node.getNumOperands() == 0;
}

bool printOperand(const SelectionDAG *DAG, const SDValue Value) {
  if (!Value.getNode()) {
    dbgs() << "<null>";
    return false;
  }

  if (shouldPrintInline(*Value.getNode())) {
    dbgs() << Value->getOperationName(DAG) << ':';
    Value->print_types(dbgs(), DAG);
    Value->print_details(dbgs(), DAG);
    return true;
  }

  dbgs() << 't' << Value.getNode()->PersistentId;
  if (unsigned RN = Value.getResNo())
    dbgs() << ':' << RN;
  return false;
}

void dumpNode(const SelectionDAG *DAG, const SDNode *Node) {
  dbgs() << 't' << Node->PersistentId << ": ";
  printTypes(Node);
  dbgs() << " = " << getOperationName(DAG, Node);
  Node->print_details(dbgs(), DAG);
  for (unsigned Idx = 0, End = Node->getNumOperands(); Idx != End; ++Idx) {
    if (Idx) dbgs() << ", "; else dbgs() << " ";
    printOperand(DAG, Node->getOperand(Idx));
  }
  dbgs() << '\n';
}

static void dumpNodes(const SelectionDAG *DAG, const SDNode *Node, unsigned Indent) {
  for (const SDValue &Op : Node->op_values()) {
    if (shouldPrintInline(*Op.getNode()))
      continue;
    if (Op.getNode()->hasOneUse())
      dumpNodes(DAG, Op.getNode(), Indent +2);
  }

  dbgs().indent(Indent);
  dumpNode(DAG, Node);
}

LLVM_DUMP_METHOD void ARMSelectionDAGISel::dumpDAG() {
  dbgs() << "SelectionDAG has " << CurDAG->allnodes_size() << " nodes:\n";

  auto *Root = CurDAG->getRoot().getNode();
  for (const SDNode &Node : CurDAG->allnodes()) {
    if (!Node.hasOneUse() && &Node != Root &&
        (!shouldPrintInline(Node) || Node.use_empty()))
      dumpNodes(CurDAG, &Node, 2);
  }

  if (CurDAG->getRoot().getNode()) dumpNodes(CurDAG, Root, 2);
  dbgs() << "\n";
}
#endif