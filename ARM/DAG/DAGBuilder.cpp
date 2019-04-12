//===- DAGBuilder.cpp - Binary raiser utility llvm-mctoll -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of DAGBuilder class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "DAGBuilder.h"
#include "ARMSubtarget.h"
#include "SelectionCommon.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include <vector>

using namespace llvm;

/// Collects the information of each MI to create SDNodes.
void DAGBuilder::visit(const MachineInstr &mi) {
  std::vector<SDValue> vctv;
  std::vector<EVT> vctt;

  for (MachineInstr::const_mop_iterator B = mi.operands_begin(),
                                        E = mi.operands_end();
       B != E; ++B) {
    const MachineOperand &mo = *B;

    if (mo.isReg() && !mo.isDebug()) {
      EVT evt = EVT::getEVT(FuncInfo.getDefaultType());
      SDValue sdv = DAG.getRegister(mo.getReg(), evt);
      vctv.push_back(sdv);
      vctt.push_back(evt);
    } else if (mo.isImm()) {
      EVT evt = FuncInfo.getDefaultEVT();
      SDValue sdv = DAG.getConstant(mo.getImm(), SDLoc(nullptr, 0), evt);
      vctv.push_back(sdv);
      vctt.push_back(evt);
    } else if (mo.isFI()) {
      int fi = mo.getIndex();
      if (FuncInfo.isStackIndex(fi)) {
        const MachineFrameInfo &mfi = mi.getMF()->getFrameInfo();
        AllocaInst *v = const_cast<AllocaInst *>(mfi.getObjectAllocation(fi));
        EVT evt = EVT::getEVT(v->getAllocatedType());
        SDValue sdv = DAG.getFrameIndex(fi, evt, false);
        DAGInfo.setRealValue(sdv.getNode(), v);
        vctv.push_back(sdv);
        vctt.push_back(evt);
      } else if (FuncInfo.isArgumentIndex(fi)) {
        Argument *v =
            const_cast<Argument *>(FuncInfo.getCRF()->arg_begin() + (fi - 1));
        EVT evt = EVT::getEVT(v->getType());
        SDValue sdv = DAG.getFrameIndex(fi, evt, false);
        DAGInfo.setRealValue(sdv.getNode(), v);
        vctv.push_back(sdv);
        vctt.push_back(evt);
      } else if (FuncInfo.isReturnIndex(fi)) {
        EVT evt = EVT::getEVT(FuncInfo.getCRF()->getReturnType());
        SDValue sdv = DAG.getFrameIndex(0, evt, false);
        vctv.push_back(sdv);
        vctt.push_back(evt);
      } else {
        // Do nothing for now.
      }
    } else if (mo.isJTI()) {
      EVT evt = EVT::getEVT(FuncInfo.getDefaultType());
      SDValue sdv = DAG.getConstant(mo.getIndex(), SDLoc(nullptr, 0), evt);
      vctv.push_back(sdv);
      vctt.push_back(evt);
    } else if (mo.isSymbol()) {
      GlobalVariable *v =
          FuncInfo.MR->getModule()->getNamedGlobal(mo.getSymbolName());
      EVT evt = EVT::getEVT(v->getValueType(), true);
      SDValue sdv = DAG.getExternalSymbol(mo.getSymbolName(), evt);
      DAGInfo.setRealValue(sdv.getNode(), v);
      vctv.push_back(sdv);
      vctt.push_back(evt);
    } else if (mo.isMetadata()) {
      const MDNode *md = mo.getMetadata();
      Type *ty = Type::getInt64Ty(FuncInfo.getCRF()->getContext());
      EVT evt = EVT::getEVT(ty);
      SDValue sdv = DAG.getMDNode(md);
      vctv.push_back(sdv);
      vctt.push_back(evt);
    } else {
      dbgs() << "Warning: visit. An unmatch type! = "
             << (unsigned)(mo.getType()) << "\n";
      mi.dump();
      mo.dump();
    }
  }

  // TODO: Add Glue value property. The cluster of MachineSDNode for schedule
  // with this, but we don't.
  vctt.push_back(MVT::Glue);

  ArrayRef<SDValue> Ops(vctv);
  ArrayRef<EVT> VTs(vctt);

  SDLoc sdl(nullptr, 0);
  MachineSDNode *mnode =
      DAG.getMachineNode(mi.getOpcode(), sdl, DAG.getVTList(VTs), Ops);

  NodePropertyInfo *npi = new NodePropertyInfo();
  npi->MI = &mi;
  DAGInfo.NPMap[mnode] = npi;

  // TODO: Now the predicate operand not stripped, so the two-address operands
  // more than two.
  // Set the Node is two-address. The default is three-address.
  if (vctv.size() < 4)
    npi->IsTwoAddress = true;

  visitCC(mi, mnode);
}

/// Analyzes CPSR register information of MI to collect conditional
/// code properties.
void DAGBuilder::visitCC(const MachineInstr &mi, MachineSDNode *mnode) {
  NodePropertyInfo &NodeInfo = *DAGInfo.NPMap[mnode];
  // Initialize the NodePropertyInfo properties.
  NodeInfo.HasCPSR = false;
  NodeInfo.Special = false;
  NodeInfo.UpdateCPSR = false;

  // ARM::CPSR register use index in MachineInstr.
  int idx = mi.findRegisterUseOperandIdx(ARM::CPSR);
  // Number of operands for MachineInstr.
  int numOps = mi.getNumOperands();

  // If the MachineInstr has ARM::CPSR register, update the NodePropertyInfo
  // properties.
  if (idx != -1 && !mi.getOperand(idx).isImplicit()) {
    // MI with ARM::CPSR register.
    if (idx != numOps - 1) {
      if (mi.getOperand(idx + 1).isReg() &&
          mi.getOperand(idx + 1).getReg() == ARM::CPSR) {
        // Pattern matching: addseq r0, r0, 0
        assert(mi.getOperand(idx - 1).isImm() &&
               "Attempt to get non-imm operand!");

        NodeInfo.Cond = mi.getOperand(idx - 1).getImm();
        NodeInfo.Special = true;
      } else {
        // Pattern matching: addeq r0, r0, 0
        for (int i = 1; i < numOps; i++) {
          if (mi.getOperand(idx - i).isImm()) {
            NodeInfo.Cond = mi.getOperand(idx - i).getImm();
            break;
          }
        }
      }
    } else {
      if (mi.getOperand(idx - 1).isReg() &&
          mi.getOperand(idx - 1).getReg() == ARM::CPSR) {
        for (int i = 1; i < numOps; i++) {
          if (mi.getOperand(idx - i).isImm()) {
            NodeInfo.Special = true;
            NodeInfo.Cond = mi.getOperand(idx - i).getImm();
            break;
          }
        }
      }
    }
    // Pattern matching: adds r0, r0, 0
    if (NodeInfo.Cond == ARMCC::AL)
      NodeInfo.UpdateCPSR = true;

    NodeInfo.HasCPSR = true;
  }
}
