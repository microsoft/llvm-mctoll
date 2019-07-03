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

// Add Reg to LiveInSet. This function adds the actual register Reg - not its
// 64-bit super register variant because we'll need the actual register to
// determine the argument type.
bool X86MachineInstructionRaiser::AddRegisterToFunctionLiveInSet(
    MCPhysRegSet &LiveInSet, unsigned Reg) {

  // Nothing to do if Reg is already in the set.
  if (LiveInSet.find(Reg) != LiveInSet.end())
    return true;

  // Find if LiveInSet already has a sub-register of Reg
  const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
  unsigned PrevLiveInReg = X86::NoRegister;
  for (MCSubRegIterator SubRegs(Reg, TRI, /*IncludeSelf=*/false);
       (SubRegs.isValid() && (PrevLiveInReg == X86::NoRegister)); ++SubRegs) {
    if (LiveInSet.find(*SubRegs) != LiveInSet.end())
      PrevLiveInReg = *SubRegs;
  }
  // If a sub-register of Reg is already in LiveInSet, replace it with Reg
  if (PrevLiveInReg != X86::NoRegister) {
    // Delete the sub-register and add the Reg
    LiveInSet.erase(PrevLiveInReg);
    // Insert UseReg
    LiveInSet.insert(Reg);
  } else {
    // No sub-register is in the current livein set.
    // Check if LiveInSet already has a super-register of Reg
    for (MCSuperRegIterator SuperRegs(Reg, TRI, /*IncludeSelf=*/false);
         (SuperRegs.isValid() && (PrevLiveInReg == X86::NoRegister));
         ++SuperRegs) {
      if (LiveInSet.find(*SuperRegs) != LiveInSet.end())
        PrevLiveInReg = *SuperRegs;
    }
    // If no super register of Reg is in current liveins, add Reg to set
    if (PrevLiveInReg == X86::NoRegister) {
      LiveInSet.insert(Reg);
    }
    // If a super-register of Reg is in LiveInSet, there is nothing to be done.
    // The fact that Reg is livein, is already noted by the presence of its
    // super register.
  }
  return true;
}

Type *X86MachineInstructionRaiser::getFunctionReturnType() {
  Type *returnType = nullptr;

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
  // Raise the jumptable
  raiseMachineJumpTable();

  if (raisedFunction == nullptr) {
    // Cleanup NOOP instructions from all MachineBasicBlocks
    deleteNOOPInstrMF();
    // Clean up any empty basic blocks
    unlinkEmptyMBBs();

    MF.getRegInfo().freezeReservedRegs(MF);
    Type *returnType = nullptr;
    std::vector<Type *> argTypeVector;

    // 1. Discover function arguments.
    // Function livein set will contain the actual registers that are livein
    // - not sub or super registers
    MCPhysRegSet FunctionLiveInRegs;
    // Set of registers defined in a block. These will be the 64-bit
    // super-registers only
    MCPhysRegSet MBBDefRegs;
    // A map of MBB number to known defined registers at the exit of the MBB
    std::map<int, MCPhysRegSet> PerMBBDefinedPhysRegMap;

    // Initialize function livein regs
    FunctionLiveInRegs.clear();
    MBBDefRegs.clear();

    // Walk the CFG DFS to discover first register usage
    LoopTraversal Traversal;
    LoopTraversal::TraversalOrder TraversedMBBOrder = Traversal.traverse(MF);
    for (LoopTraversal::TraversedMBBInfo TraversedMBB : TraversedMBBOrder) {
      MachineBasicBlock *MBB = TraversedMBB.MBB;
      if (MBB->empty())
        continue;
      int MBBNo = MBB->getNumber();
      MBBDefRegs.clear();
      // TODO: LoopTraversal assumes fully-connected CFG. However, need to
      // handle blocks with terminator instruction that could potentially result
      // in a disconnected CFG - such as branch with register target.
      MachineInstr &TermInst = MBB->instr_back();
      if (TermInst.isBranch()) {
        auto OpType = TermInst.getOperand(0).getType();
        assert(((OpType == MachineOperand::MachineOperandType::MO_Immediate) ||
                (OpType ==
                 MachineOperand::MachineOperandType::MO_JumpTableIndex)) &&
               "Unexpected block terminator found during function prototype "
               "discovery");
      }
      // Union of defined registers of all predecessors
      for (auto PredMBB : MBB->predecessors()) {
        auto MapIter = PerMBBDefinedPhysRegMap.find(PredMBB->getNumber());
        // Register defs of all predecessors may not be available if MBB is not
        // ready for final round of processing.
        if (MapIter != PerMBBDefinedPhysRegMap.end()) {
          for (auto V : MapIter->second) {
            MBBDefRegs.insert(V);
          }
        } else {
          // Check to make sure that traversed MBB is not done if register defs
          // of one of the predecessors is not available.
          // assert(!TraversedMBB.IsDone && "Unexpected register definition
          // state "
          //                               "during function prototype
          //                               discovery");
        }
      }

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

          // If the source regs are not the same
          if (Use1Op.getReg() != Use2Op.getReg()) {
            // If the source register has not been used before, add it to the
            // list of first use registers.
            unsigned UseReg = Use1Op.getReg();
            if (MBBDefRegs.find(find64BitSuperReg(UseReg)) ==
                MBBDefRegs.end()) {
              AddRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
            }
            UseReg = Use2Op.getReg();
            if (MBBDefRegs.find(find64BitSuperReg(UseReg)) ==
                MBBDefRegs.end()) {
              AddRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
            }
          }
          // Add def reg to MBBDefRegs set
          MBBDefRegs.insert(find64BitSuperReg(DestOp.getReg()));
        } else {
          for (MachineOperand MO : MI.operands()) {
            if (!MO.isReg())
              continue;
            unsigned Reg = MO.getReg();
            if (!TargetRegisterInfo::isPhysicalRegister(Reg) ||
                (Reg == X86::EFLAGS) || (Reg == X86::SSP) ||
                X86MCRegisterClasses[X86::RSTRegClassID].contains(Reg))
              continue;

            if (MO.isUse()) {
              // If Reg use has no previous def
              if (MBBDefRegs.find(find64BitSuperReg(Reg)) == MBBDefRegs.end())
                AddRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
              else {
                // Reg has a previous definition. Make sure that
                // FunctionLiveInRegs does not gave Reg.
                // NOTE : This situation may be seen during non-primary pass of
                // the loop traversal of the CFG. Nonetheless, it is correct in
                // all passes.
                // if (FunctionLiveInRegs.find(Reg) != FunctionLiveInRegs.end())
                //  FunctionLiveInRegs.erase(Reg);
              }
            } else if (MO.isDef()) {
              MBBDefRegs.insert(find64BitSuperReg(Reg));
            }
          }
        }
      }
      // Per-MBB reg def info is expected to exist only if this is not the
      // primary pass of the MBB.
      assert(((PerMBBDefinedPhysRegMap.find(MBBNo) ==
               PerMBBDefinedPhysRegMap.end()) ||
              ((PerMBBDefinedPhysRegMap.find(MBBNo) !=
                PerMBBDefinedPhysRegMap.end()) &&
               (!TraversedMBB.PrimaryPass))) &&
             "Unexpected state of register definition information during "
             "function prototype discovery");
      MCPhysRegSet MBBDefRegSet;
      for (auto R : MBBDefRegs) {
        MBBDefRegSet.insert(R);
      }
      PerMBBDefinedPhysRegMap[MBBNo] = MBBDefRegSet;
    }

    // Use the first register usage list to form argument vector using first
    // argument register usage.
    buildFuncArgTypeVector(FunctionLiveInRegs, argTypeVector);
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
  int MaxArgNum = 0;

  for (MCPhysReg PReg : PhysRegs) {
    // If Reg is an argument register per C standard calling convention
    // construct function argument.
    int argNum = getArgumentNumber(PReg);

    if (argNum > 0) {
      if (argNum > MaxArgNum)
        MaxArgNum = argNum;

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
  for (int i = 1; i <= MaxArgNum; i++) {
    auto argIter = argNumTypeMap.find(i);
    if (argIter == argNumTypeMap.end()) {
      // Argument register not used. It is most likely optimized.
      // The argument is not used. Safe to consider it to be of 64-bit type.
      ArgTyVec.push_back(Type::getInt64Ty(funcLLVMContext));
    } else {
      ArgTyVec.push_back(argNumTypeMap.find(i)->second);
    }
  }
  return true;
}
