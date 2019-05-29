//===-- X86FuncPrototypeDiscovery.cpp -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of function prototype discovey APIs of
// X86MachineInstructionRaiser class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ExternalFunctions.h"
#include "MachineFunctionRaiser.h"
#include "X86InstrBuilder.h"
#include "X86MachineInstructionRaiser.h"
#include "X86ModuleRaiser.h"
#include "X86RaisedValueTracker.h"
#include "X86RegisterUtils.h"
#include "llvm-mctoll.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/LoopTraversal.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <set>
#include <vector>
using namespace llvm;
using namespace mctoll;
using namespace X86RegisterUtils;

// Return argument number associated with physical
// register PReg according to C calling convention.

int X86MachineInstructionRaiser::getArgumentNumber(unsigned PReg) {
  int pos = -1;
  if (is8BitPhysReg(PReg)) {
    int diff = std::distance(
        GPR64ArgRegs8Bit.begin(),
        std::find(GPR64ArgRegs8Bit.begin(), GPR64ArgRegs8Bit.end(), PReg));
    if ((diff >= 0) && (diff < (int)GPR64ArgRegs8Bit.size())) {
      pos = diff + 1;
    }
  } else if (is16BitPhysReg(PReg)) {
    int diff = std::distance(
        GPR64ArgRegs16Bit.begin(),
        std::find(GPR64ArgRegs16Bit.begin(), GPR64ArgRegs16Bit.end(), PReg));
    if ((diff >= 0) && (diff < (int)GPR64ArgRegs16Bit.size())) {
      pos = diff + 1;
    }
  } else if (is32BitPhysReg(PReg)) {
    int diff = std::distance(
        GPR64ArgRegs32Bit.begin(),
        std::find(GPR64ArgRegs32Bit.begin(), GPR64ArgRegs32Bit.end(), PReg));
    if ((diff >= 0) && (diff < (int)GPR64ArgRegs32Bit.size())) {
      pos = diff + 1;
    }
  } else if (is64BitPhysReg(PReg)) {
    int diff = std::distance(
        GPR64ArgRegs64Bit.begin(),
        std::find(GPR64ArgRegs64Bit.begin(), GPR64ArgRegs64Bit.end(), PReg));
    if ((diff >= 0) && (diff < (int)GPR64ArgRegs64Bit.size())) {
      pos = diff + 1;
    }
  }
  return pos;
}

Type *X86MachineInstructionRaiser::getFunctionReturnType() {
  Type *returnType = nullptr;
  SmallVector<MachineBasicBlock *, 8> WorkList;
  BitVector BlockVisited(MF.getNumBlockIDs(), false);

  assert(x86TargetInfo.is64Bit() && "Only x86_64 binaries supported for now");

  // Find a return block. It is sufficient to get one of the return blocks to
  // find the return type. This type should be the same on any of the paths from
  // entry to any other return blocks.
  MachineBasicBlock *RetBlock = nullptr;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.isReturnBlock()) {
      RetBlock = &MBB;
      break;
    }
  }

  if (RetBlock != nullptr) {
    returnType = getReturnTypeFromMBB(*RetBlock);
  }

  // If we are unable to discover the return type assume that the return
  // type is void.
  if (returnType == nullptr)
    returnType = Type::getVoidTy(MF.getFunction().getContext());

  return returnType;
}

// Construct prototype of the Function for the MachineFunction being raised.
FunctionType *X86MachineInstructionRaiser::getRaisedFunctionPrototype() {

  if (raisedFunction == nullptr) {
    // Cleanup NOOP instructions from all MachineBasicBlocks
    deleteNOOPInstrMF();
    // Clean up any empty basic blocks
    unlinkEmptyMBBs();

    MF.getRegInfo().freezeReservedRegs(MF);
    Type *returnType = nullptr;
    std::vector<Type *> argTypeVector;

    // 1. Discover function arguments.
    // Build live-ins for all blocks
    LivePhysRegs liveInPhysRegs;
    for (MachineBasicBlock &MBB : MF) {
      computeAndAddLiveIns(liveInPhysRegs, MBB);
    }

    // Walk the CFG DFS to discover first register usage
    std::set<MCPhysReg> LiveInRegs;
    MachineBasicBlock *Entry = &(MF.front());
    df_iterator_default_set<MachineBasicBlock *, 16> Visited;
    // List of registers used in a block
    LivePhysRegs MBBUseRegs;
    // List of registers that are cleared by an xor instruction prior to its
    // first use.
    LivePhysRegs PseudoUseRegs;
    const MachineRegisterInfo &MRI = MF.getRegInfo();
    const TargetRegisterInfo *TRI = MRI.getTargetRegisterInfo();
    MBBUseRegs.init(*TRI);
    PseudoUseRegs.init(*TRI);

    for (MachineBasicBlock *MBB : depth_first_ext(Entry, Visited)) {
      MBBUseRegs.clear();
      for (MachineBasicBlock::iterator Iter = MBB->instr_begin(),
                                       End = MBB->instr_end();
           Iter != End; Iter++) {
        MachineInstr &MI = *Iter;
        unsigned Opc = MI.getOpcode();

        // xor reg, reg is a typical idiom used to clear reg. If reg happens
        // to be an argument register, it should not be considered as such.
        // Record it as such.
        if (Opc == X86::XOR64rr || Opc == X86::XOR32rr || Opc == X86::XOR16rr ||
            Opc == X86::XOR8rr) {
          unsigned DestOpIndx = 0, SrcOp1Indx = 1, SrcOp2Indx = 2;
          const MachineOperand &DestOp = MI.getOperand(DestOpIndx);
          const MachineOperand &Use1Op = MI.getOperand(SrcOp1Indx);
          const MachineOperand &Use2Op = MI.getOperand(SrcOp2Indx);

          assert(Use1Op.isReg() && Use2Op.isReg() && DestOp.isReg() &&
                 (MI.findTiedOperandIdx(SrcOp1Indx) == DestOpIndx) &&
                 "Expecting register operands of xor instruction");

          if (Use1Op.getReg() == Use2Op.getReg())
            // If the source register has not been used before, add it to the
            // list of registers that should not be considered as first use
            if (!MBBUseRegs.contains(Use1Op.getReg()))
              // Record the 64-bit version of the register. Note that addReg()
              // adds the register and all its sub-registers to the set. The
              // corresponding set-membership test contains(), tests for the
              // register and all its sub-registers.
              PseudoUseRegs.addReg(find64BitSuperReg(DestOp.getReg()));
        } else {
          MBBUseRegs.addUses(MI);
        }
      }

      for (const auto &LI : MBB->liveins()) {
        MCPhysReg PhysReg = LI.PhysReg;
        // Is PhysReg in pseudo-use register list?
        bool found = PseudoUseRegs.contains(PhysReg);
        // Check if any of the sub-registers of PhysReg is in LiveRegs
        for (MCSubRegIterator SubRegs(PhysReg, TRI, /*IncludeSelf=*/true);
             (SubRegs.isValid() && !found); ++SubRegs) {
          found = (LiveInRegs.find(*SubRegs) != LiveInRegs.end());
        }
        // Check if any of the super-registers of PhysReg is in LiveRegs
        for (MCSuperRegIterator SupRegs(PhysReg, TRI, /*IncludeSelf=*/true);
             (SupRegs.isValid() && !found); ++SupRegs) {
          found = (LiveInRegs.find(*SupRegs) != LiveInRegs.end());
        }
        // If neither sub or super registers of PhysReg is in LiveRegs set and
        // PhysReg is not in pseudo-usage list, then add it to the list of
        // liveins.
        if (!found)
          LiveInRegs.emplace(LI.PhysReg);
      }
    }
    // Use the first register usage list to form argument vector using first
    // argument register usage.
    buildFuncArgTypeVector(LiveInRegs, argTypeVector);
    // 2. Discover function return type
    returnType = getFunctionReturnType();

    // The Function object associated with current MachineFunction object
    // is only a place holder. It was created to facilitate creation of
    // MachineFunction object with a prototype void functionName(void).
    // The Module object contains this place-holder Function object in its
    // FunctionList. Since the return type and arguments are now discovered,
    // we need to replace this place holder Function object in module with
    // the correct Function object being created now.
    // 1. Get the current function name
    StringRef functionName = MF.getFunction().getName();
    Module *module = MR->getModule();
    // 2. Get the corresponding Function* registered in module
    Function *tempFunctionPtr = module->getFunction(functionName);
    assert(tempFunctionPtr != nullptr && "Function not found in module list");
    // 4. Delete the tempFunc from module list to allow for the creation of
    //    the real function to add the correct one to FunctionList of the
    //    module.
    module->getFunctionList().remove(tempFunctionPtr);
    // 3. Now create a function type using the discovered argument
    //    types and return value.
    FunctionType *FT =
        FunctionType::get(returnType, argTypeVector, false /* isVarArg*/);
    // 4. Create the real Function now that we have discovered the
    // arguments.
    raisedFunction = Function::Create(FT, GlobalValue::ExternalLinkage,
                                      functionName, module);

    // Set global linkage
    raisedFunction->setLinkage(GlobalValue::ExternalLinkage);
    // Set C calling convention
    raisedFunction->setCallingConv(CallingConv::C);
    // Set the function to be in the same linkage unit
    raisedFunction->setDSOLocal(true);
    // TODO : Set other function attributes as needed.
    // Add argument names to the function.
    // Note: Call to arg_begin() calls Function::BuildLazyArguments()
    // to build the arguments.
    Function::arg_iterator ArgIt = raisedFunction->arg_begin();
    unsigned numFuncArgs = raisedFunction->arg_size();
    StringRef prefix("arg");
    for (unsigned i = 0; i < numFuncArgs; ++i, ++ArgIt) {
      // Set the name.
      ArgIt->setName(prefix + std::to_string(i + 1));
    }

    // Insert the map of raised function to tempFunctionPointer.
    const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
        raisedFunction, tempFunctionPtr);
  }

  return raisedFunction->getFunctionType();
}

// Discover and return the return-type using the return block MBB.
// Return type is constructed based on the last definition of RAX (or its
// sub-register) in MBB. If no such definition definition is found, return type
// is constructed based on RAX (or its sub-register) being part of MBB's
// live-ins.
Type *
X86MachineInstructionRaiser::getReturnTypeFromMBB(MachineBasicBlock &MBB) {
  Type *returnType = nullptr;

  assert(MBB.isReturnBlock() &&
         "Attempt to discover return type from a non-return MBB");
  // Check liveness of EAX in the return block. We assume that EAX (or
  // RAX) would have to be defined in the return block.
  // TODO : We may have to revisit this assumption, if needed.

  // Walk the return block backwards
  MachineBasicBlock::const_iterator I(MBB.back());
  if (I != MBB.begin()) {
    do {
      --I;
      // Do not inspect the last call instruction or instructions prior to
      // the last call instruction.
      if (I->isCall())
        break;

      unsigned DefReg = X86::NoRegister;
      const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
      // Check if any of RAX, EAX, AX or AL are explicitly defined
      if (I->getDesc().getNumDefs() != 0) {
        const MachineOperand &MO = I->getOperand(0);
        if (MO.isReg()) {
          unsigned PReg = MO.getReg();
          if (!TargetRegisterInfo::isPhysicalRegister(PReg)) {
            continue;
          }
          // Check if PReg is any of the sub-registers of RAX (including
          // itself)
          for (MCSubRegIterator SubRegs(X86::RAX, TRI, /*IncludeSelf=*/true);
               (SubRegs.isValid() && DefReg == X86::NoRegister); ++SubRegs) {
            if (*SubRegs == PReg) {
              DefReg = *SubRegs;
              break;
            }
          }
        }
      }
      // If explicitly defined register is not a return register, check if any
      // of the sub-registers of RAX (including itself) is implicitly defined.
      for (MCSubRegIterator SubRegs(X86::RAX, TRI, /*IncludeSelf=*/true);
           (SubRegs.isValid() && DefReg == X86::NoRegister); ++SubRegs) {
        if (I->getDesc().hasImplicitDefOfPhysReg(*SubRegs, TRI)) {
          DefReg = *SubRegs;
          break;
        }
      }

      // If the defined register is a return register
      if (DefReg != X86::NoRegister) {
        if (!TargetRegisterInfo::isPhysicalRegister(DefReg)) {
          continue;
        }
        if (DefReg == X86::RAX) {
          if (returnType == nullptr) {
            returnType = Type::getInt64Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 64 &&
                   "Inconsistency while discovering return type");
          }
        } else if (DefReg == X86::EAX) {
          if (returnType == nullptr) {
            returnType = Type::getInt32Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 32 &&
                   "Inconsistency while discovering return type");
          }
        } else if (DefReg == X86::AX) {
          if (returnType == nullptr) {
            returnType = Type::getInt16Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 16 &&
                   "Inconsistency while discovering return type");
          }
        } else if (DefReg == X86::AL) {
          if (returnType == nullptr) {
            returnType = Type::getInt8Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 8 &&
                   "Inconsistency while discovering return type");
          }
        }
      }
    } while (I != MBB.begin());
  }

  // If return type not found
  if (returnType == nullptr) {
    // Check if return register is a live-in i.e., if the sub-registers of RAX
    // (including itself) is live-in
    unsigned LIRetReg = X86::NoRegister;
    const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();

    for (const auto &LI : MBB.liveins()) {
      MCPhysReg PhysReg = LI.PhysReg;

      for (MCSubRegIterator SubRegs(X86::RAX, TRI, /*IncludeSelf=*/true);
           (SubRegs.isValid() && LIRetReg == X86::NoRegister); ++SubRegs) {
        if (*SubRegs == PhysReg) {
          LIRetReg = *SubRegs;
        }
      }
    }
    if (LIRetReg != X86::NoRegister)
      returnType = getPhysRegType(LIRetReg);
  }

  return returnType;
}

// Construct argument type vector from the physical register vector.
// Requirements : PhysRegs is a set of registers each with no super or
// sub-registers.
bool X86MachineInstructionRaiser::buildFuncArgTypeVector(
    const std::set<MCPhysReg> &PhysRegs, std::vector<Type *> &ArgTyVec) {
  // A map of argument number and type as discovered
  std::map<unsigned int, Type *> argNumTypeMap;
  llvm::LLVMContext &funcLLVMContext = MF.getFunction().getContext();

  for (MCPhysReg PReg : PhysRegs) {
    // If Reg is an argument register per C standard calling convention
    // construct function argument.
    int argNum = getArgumentNumber(PReg);

    if (argNum > 0) {
      // Make sure each argument position is discovered only once
      assert(argNumTypeMap.find(argNum) == argNumTypeMap.end());
      if (is8BitPhysReg(PReg)) {
        argNumTypeMap.insert(
            std::make_pair(argNum, Type::getInt8Ty(funcLLVMContext)));
      } else if (is16BitPhysReg(PReg)) {
        argNumTypeMap.insert(
            std::make_pair(argNum, Type::getInt16Ty(funcLLVMContext)));
      } else if (is32BitPhysReg(PReg)) {
        argNumTypeMap.insert(
            std::make_pair(argNum, Type::getInt32Ty(funcLLVMContext)));
      } else if (is64BitPhysReg(PReg)) {
        argNumTypeMap.insert(
            std::make_pair(argNum, Type::getInt64Ty(funcLLVMContext)));
      } else {
        outs() << x86RegisterInfo->getRegAsmName(PReg) << "\n";
        assert(false && "Unhandled register type encountered in binary");
      }
    }
  }

  // Build argument type vector that will be used to build FunctionType
  // while sanity checking arguments discovered
  for (unsigned int i = 1; i <= argNumTypeMap.size(); i++) {
    // If the function has arguments, we assume that the conventional
    // argument registers are used in order. If the arg register
    // corresponding to position i is not a live in, it implies that the
    // function has i-1 arguments.
    if (argNumTypeMap.find(i) == argNumTypeMap.end()) {
      break;
    }
    auto Ty = argNumTypeMap.find(i)->second;
    ArgTyVec.push_back(Ty);
  }
  return true;
}
