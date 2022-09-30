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

#include "ARMSubtarget.h"
#include "DAGBuilder.h"
#include "SelectionCommon.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include <vector>

using namespace llvm;
using namespace llvm::mctoll;

/// Collects the information of each MI to create SDNodes.
void DAGBuilder::visit(const MachineInstr &MI) {
  std::vector<SDValue> VCtv;
  std::vector<EVT> VCtt;

  for (MachineInstr::const_mop_iterator B = MI.operands_begin(),
                                        E = MI.operands_end();
       B != E; ++B) {
    const MachineOperand &MO = *B;

    if (MO.isReg() && !MO.isDebug()) {
      EVT Evt = EVT::getEVT(FuncInfo.getDefaultType());
      SDValue Sdv = DAG.getRegister(MO.getReg(), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isImm()) {
      EVT Evt = FuncInfo.getDefaultEVT();
      SDValue Sdv = DAG.getConstant(MO.getImm(), SDLoc(nullptr, 0), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isFI()) {
      // Frame index
      int FI = MO.getIndex();
      if (FuncInfo.isStackIndex(FI)) {
        const MachineFrameInfo &MFI = MI.getMF()->getFrameInfo();
        AllocaInst *V = const_cast<AllocaInst *>(MFI.getObjectAllocation(FI));
        EVT Evt = EVT::getEVT(V->getAllocatedType());
        SDValue Sdv = DAG.getFrameIndex(FI, Evt, false);
        DAGInfo.setRealValue(Sdv.getNode(), V);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else if (FuncInfo.isArgumentIndex(FI)) {
        Argument *V =
            const_cast<Argument *>(FuncInfo.getCRF()->arg_begin() + (FI - 1));
        EVT Evt = EVT::getEVT(V->getType());
        SDValue Sdv = DAG.getFrameIndex(FI, Evt, false);
        DAGInfo.setRealValue(Sdv.getNode(), V);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else if (FuncInfo.isReturnIndex(FI)) {
        EVT Evt = EVT::getEVT(FuncInfo.getCRF()->getReturnType());
        SDValue Sdv = DAG.getFrameIndex(0, Evt, false);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else {
        // Do nothing for now.
      }
    } else if (MO.isJTI()) {
      // Jump table index
      EVT Evt = EVT::getEVT(FuncInfo.getDefaultType());
      SDValue Sdv = DAG.getConstant(MO.getIndex(), SDLoc(nullptr, 0), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isSymbol()) {
      GlobalVariable *V =
          FuncInfo.MR->getModule()->getNamedGlobal(MO.getSymbolName());
      EVT Evt = EVT::getEVT(V->getValueType(), true);
      SDValue Sdv = DAG.getExternalSymbol(MO.getSymbolName(), Evt);
      DAGInfo.setRealValue(Sdv.getNode(), V);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isMetadata()) {
      const MDNode *MD = MO.getMetadata();
      Type *Ty = Type::getInt64Ty(FuncInfo.getCRF()->getContext());
      EVT Evt = EVT::getEVT(Ty);
      SDValue Sdv = DAG.getMDNode(MD);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else {
      dbgs() << "Warning: visit. An unmatch type! = "
             << (unsigned)(MO.getType()) << "\n";
    }
  }

  // TODO: Add Glue value property. The cluster of MachineSDNode for schedule
  // with this, but we don't.
  VCtt.push_back(MVT::Glue);

  ArrayRef<SDValue> Ops(VCtv);
  ArrayRef<EVT> VTs(VCtt);

  SDLoc Sdl(nullptr, 0);
  MachineSDNode *MNode =
      DAG.getMachineNode(MI.getOpcode(), Sdl, DAG.getVTList(VTs), Ops);

  NodePropertyInfo *NPI = new NodePropertyInfo();
  NPI->MI = &MI;
  DAGInfo.NPMap[MNode] = NPI;

  // TODO: Now the predicate operand not stripped, so the two-address operands
  // more than two.
  // Set the Node is two-address. The default is three-address.
  if (VCtv.size() < 4)
    NPI->IsTwoAddress = true;

  visitCC(MI, MNode);
}

/// Analyzes CPSR register information of MI to collect conditional
/// code properties.
void DAGBuilder::visitCC(const MachineInstr &MI, MachineSDNode *MNode) {
  NodePropertyInfo &NodeInfo = *DAGInfo.NPMap[MNode];
  // Initialize the NodePropertyInfo properties.
  NodeInfo.HasCPSR = false;
  NodeInfo.Special = false;
  NodeInfo.UpdateCPSR = false;

  // ARM::CPSR register use index in MachineInstr.
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Number of operands for MachineInstr.
  int NumOps = MI.getNumOperands();

  // If the MachineInstr has ARM::CPSR register, update the NodePropertyInfo
  // properties.
  if (Idx != -1 && !MI.getOperand(Idx).isImplicit()) {
    // MI with ARM::CPSR register.
    if (Idx != NumOps - 1) {
      if (MI.getOperand(Idx + 1).isReg() &&
          MI.getOperand(Idx + 1).getReg() == ARM::CPSR) {
        // Pattern matching: addseq r0, r0, 0
        assert(MI.getOperand(Idx - 1).isImm() &&
               "Attempt to get non-imm operand!");

        NodeInfo.Cond = MI.getOperand(Idx - 1).getImm();
        NodeInfo.Special = true;
      } else {
        // Pattern matching: addeq r0, r0, 0
        for (int OpIdx = 1; OpIdx < NumOps; OpIdx++) {
          if (MI.getOperand(Idx - OpIdx).isImm()) {
            NodeInfo.Cond = MI.getOperand(Idx - OpIdx).getImm();
            break;
          }
        }
      }
    } else {
      if (MI.getOperand(Idx - 1).isReg() &&
          MI.getOperand(Idx - 1).getReg() == ARM::CPSR) {
        for (int OpIdx = 1; OpIdx < NumOps; OpIdx++) {
          if (MI.getOperand(Idx - OpIdx).isImm()) {
            NodeInfo.Special = true;
            NodeInfo.Cond = MI.getOperand(Idx - OpIdx).getImm();
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
