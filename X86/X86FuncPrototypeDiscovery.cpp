//===-- X86FuncPrototypeDiscovery.cpp ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of function prototype discovery APIs of
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
#include <X86Subtarget.h>
#include <set>
#include <vector>
using namespace llvm;
using namespace mctoll;
using namespace X86RegisterUtils;

// A convenience function that is slightly different from the LLVM API viz.,
// MCInstrDesc::hasImplicitDefOfPhysReg() which returns true if Reg or its
// sub-register is an implicit definition. In contrast, this function returns
// true only if Reg is an implicit definition.
static bool hasExactImplicitDefOfPhysReg(const MachineInstr &I, unsigned Reg,
                                         const MCRegisterInfo *MRI) {
  if (const MCPhysReg *ImpDefs = I.getDesc().ImplicitDefs)
    for (; *ImpDefs; ++ImpDefs)
      if (*ImpDefs == Reg)
        return true;
  return false;
}

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
void X86MachineInstructionRaiser::addRegisterToFunctionLiveInSet(
    MCPhysRegSet &LiveInSet, unsigned Reg) {

  // Nothing to do if Reg is already in the set.
  if (LiveInSet.find(Reg) != LiveInSet.end())
    return;

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
    return;
  }

  // No sub-register is in the current livein set.
  // Check if LiveInSet already has a super-register of Reg
  for (MCSuperRegIterator SuperRegs(Reg, TRI, /*IncludeSelf=*/false);
       (SuperRegs.isValid() && (PrevLiveInReg == X86::NoRegister));
       ++SuperRegs) {
    if (LiveInSet.find(*SuperRegs) != LiveInSet.end())
      PrevLiveInReg = *SuperRegs;
  }

  // If no super register of Reg is in current liveins, add Reg to set
  if (PrevLiveInReg == X86::NoRegister)
    LiveInSet.insert(Reg);

  // If a super-register of Reg is in LiveInSet, there is nothing to be done.
  // The fact that Reg is livein, is already noted by the presence of its
  // super register.
}

Type *X86MachineInstructionRaiser::getFunctionReturnType() {
  Type *returnType = nullptr;

  assert(x86TargetInfo.is64Bit() && "Only x86_64 binaries supported for now");

  // Find a return block. It is sufficient to get one of the return blocks to
  // find the return type. This type should be the same on any of the paths from
  // entry to any other return blocks.
  SmallVector<MachineBasicBlock *, 8> WorkList;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.isReturnBlock()) {
      // Add the predecessors of return block to the list as candidates
      // of blocks to look for the instruction that sets return register, in
      // case it is not found in the return block.
      for (auto Pred : MBB.predecessors())
        WorkList.push_back(Pred);
      // Now push return block to ensure we start looking at the return block
      // first.
      WorkList.push_back(&MBB);
      break;
    }
  }

  bool BlockHasCall = false;

  while (!WorkList.empty() && returnType == nullptr) {
    MachineBasicBlock *MBB = WorkList.pop_back_val();
    // If return register is defined in MBB, return the appropriate type.
    // 1. Get the register definition map of MBB
    auto MBBDefinedPhysRegIter = PerMBBDefinedPhysRegMap.find(MBB->getNumber());
    if (MBBDefinedPhysRegIter != PerMBBDefinedPhysRegMap.end()) {
      // If found, get the value defined for X86::RAX
      MCPhysRegSizeMap DefinedPhysRegMap = MBBDefinedPhysRegIter->second;
      auto DefinedPhysRegMapIter = DefinedPhysRegMap.find(X86::RAX);
      // If RAX is defined by the end of the block, get the type.
      // NOTE: The fact that return register is defined at the end of the block
      // does not imply that a return type would be found. In cases where the
      // return register might have been defined before the last call
      // instruction in the block but not after that call instruction determines
      // if we can deduce the return type.
      if (DefinedPhysRegMapIter != DefinedPhysRegMap.end()) {
        returnType = getReturnTypeFromMBB(*MBB, BlockHasCall);
        // Check the correctness of the type, if found.
        if (returnType != nullptr) {
          assert((returnType->getPrimitiveSizeInBits() ==
                  DefinedPhysRegMapIter->second * 8) &&
                 "Inconsistent return type found");
        }
        // If the block has a call instruction, stop looking for the instruction
        // that sets return register.
        if (BlockHasCall)
          break;
      }
    }
  }

  // If we are unable to discover the return type, check if the function has
  // tail calls
  if (returnType == nullptr) {
    for (MachineBasicBlock &MBB : MF) {
      int MBBNo = MBB.getNumber();
      if (tailCallMBBNos.find(MBBNo) != tailCallMBBNos.end()) {
        // Get the register definition map of MBB
        auto MBBDefinedPhysRegIter = PerMBBDefinedPhysRegMap.find(MBBNo);
        if (MBBDefinedPhysRegIter != PerMBBDefinedPhysRegMap.end()) {
          // If found, get the value defined for X86::RAX
          MCPhysRegSizeMap DefinedPhysRegMap = MBBDefinedPhysRegIter->second;
          auto DefinedPhysRegMapIter = DefinedPhysRegMap.find(X86::RAX);
          // If RAX is defined by the end of the block, get the type. If found,
          // this is a block with tail call. So, the return of the tail call is
          // the return of this function as well.
          if (DefinedPhysRegMapIter != DefinedPhysRegMap.end()) {
            returnType = Type::getIntNTy(MF.getFunction().getContext(),
                                         DefinedPhysRegMapIter->second * 8);
            // We do not need to look for other blocks with tail calls because
            // all of them should have the same return values.
            break;
          }
        }
      }
    }
  }
  // If return type is still not discovered, assume it to be void
  if (returnType == nullptr)
    returnType = Type::getVoidTy(MF.getFunction().getContext());

  return returnType;
}

// Construct prototype of the Function for the MachineFunction being
// raised.
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
    // Function livein set will contain the actual registers that are
    // livein
    // - not sub or super registers
    MCPhysRegSet FunctionLiveInRegs;
    // Set of registers defined in a block. These will be the 64-bit
    // super-register mapping to associated usage size.
    // NOTE: Using a map to record the access size instead of using the
    // LivePhysRegs type, since the binary code can define a sub-register
    // (e.g., $ecx) but use its super-register (e.g., $rcx). Such
    // situations can not be modeled using the LivePhysRegs::addReg API
    // since it only adds the reg and its sub-registers.
    MCPhysRegSizeMap MBBDefRegs;

    // Walk the CFG DFS to discover first register usage
    LoopTraversal Traversal;
    LoopTraversal::TraversalOrder TraversedMBBOrder = Traversal.traverse(MF);
    for (LoopTraversal::TraversedMBBInfo TraversedMBB : TraversedMBBOrder) {
      MachineBasicBlock *MBB = TraversedMBB.MBB;
      if (MBB->empty())
        continue;
      int MBBNo = MBB->getNumber();
      tailCallMBBNos.clear();
      MBBDefRegs.clear();
      // TODO: LoopTraversal assumes fully-connected CFG. However, need to
      // handle blocks with terminator instruction that could potentially
      // result in a disconnected CFG - such as branch with register
      // target.
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
        auto PredMBBRegDefSizeIter =
            PerMBBDefinedPhysRegMap.find(PredMBB->getNumber());
        // Register defs of all predecessors may not be available if MBB
        // is not ready for final round of processing.
        if (PredMBBRegDefSizeIter != PerMBBDefinedPhysRegMap.end()) {
          for (auto PredMBBRegDefSizePair : PredMBBRegDefSizeIter->second) {
            // If there was an earlier definition in another predecessor,
            // make sure the size is greater than or equal to the current
            // definition.
            auto SuperReg = PredMBBRegDefSizePair.first;
            auto PrevMBBRegDefSizePairIter = MBBDefRegs.find(SuperReg);
            auto PredMBBDefSz = PredMBBRegDefSizePair.second;
            if (PrevMBBRegDefSizePairIter != MBBDefRegs.end()) {
              if (PredMBBDefSz > PrevMBBRegDefSizePairIter->second) {
                MBBDefRegs.erase(SuperReg);
                MBBDefRegs[SuperReg] = PredMBBDefSz;
              }
              // Else, just retain the existing entry
            } else {
              // No entry for SuperReg in the union being constructed. Add
              // one.
              MBBDefRegs[SuperReg] = PredMBBDefSz;
            }
          }
        }
      }

      for (MachineBasicBlock::iterator Iter = MBB->instr_begin(),
                                       End = MBB->instr_end();
           Iter != End; Iter++) {
        MachineInstr &MI = *Iter;
        unsigned Opc = MI.getOpcode();
        // MI is not a tail call instruction, unless determined otherwise.
        bool IsTailCall = false;

        // xor reg, reg is a typical idiom used to clear reg. If reg
        // happens to be an argument register, it should not be considered
        // as such. Record it as such.
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
            // If the source register has not been used before, add it to
            // the list of first use registers.
            unsigned UseReg = Use1Op.getReg();
            if (MBBDefRegs.find(find64BitSuperReg(UseReg)) ==
                MBBDefRegs.end()) {
              addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
            }
            UseReg = Use2Op.getReg();
            if (MBBDefRegs.find(find64BitSuperReg(UseReg)) ==
                MBBDefRegs.end()) {
              addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
            }
          }
          // Add def reg to MBBDefRegs set
          unsigned DestReg = DestOp.getReg();
          // We need the last definition. Even if there is a previous
          // definition, it is correct to just over write the size
          // information.
          MBBDefRegs[find64BitSuperReg(DestReg)] =
              getPhysRegSizeInBits(DestReg) / 8;
        } else if (MI.isCall() || MI.isUnconditionalBranch()) {
          // If this is an unconditional branch, check if it is a tail
          // call.
          if (MI.isUnconditionalBranch()) {
            if ((MI.getNumOperands() > 0) && MI.getOperand(0).isImm()) {
              // Only if this is a direct branch instruction with an
              // immediate offset
              const MCInstrDesc MCID = MI.getDesc();
              if (X86II::isImmPCRel(MCID.TSFlags)) {
                // Get branch offset of the branch instruction
                const MachineOperand &MO = MI.getOperand(0);
                assert(MO.isImm() && "Expected immediate operand not found");
                int64_t BranchOffset = MO.getImm();
                MCInstRaiser *MCIR = getMCInstRaiser();
                // Get MCInst offset - the offset of machine instruction
                // in the binary
                uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);

                assert(MCIR != nullptr && "MCInstRaiser not initialized");
                int64_t BranchTargetOffset = MCInstOffset +
                                             MCIR->getMCInstSize(MCInstOffset) +
                                             BranchOffset;
                // If there is no MBB corresponding to branch target
                // offset, this may be a tail call.
                if (MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset) ==
                    -1) {
                  // It is a tail call only if there are no other
                  // instructions after this unconditional branch
                  // instruction.
                  IsTailCall = (MI.getNextNode() == nullptr);
                }
              }
            }
          }
          // If the instruction is a call or a potential tail call,
          // attempt to find the called function.
          if (MI.isCall() || IsTailCall) {
            // Check if the first use of argument registers is as
            // arguments of a call or a tail-call.
            unsigned int Opcode = MI.getOpcode();
            if ((Opcode == X86::CALL64pcrel32) || (Opcode == X86::JMP_4) ||
                (Opcode == X86::JMP_1)) {
              Function *CalledFunc = getCalledFunction(MI);
              // If the called function is found, consider argument
              // registers as use registers.
              if (CalledFunc != nullptr) {
                unsigned ArgRegVecIndex = 0;
                for (auto &Arg : CalledFunc->args()) {
                  unsigned Reg =
                      getArgumentReg(ArgRegVecIndex++, Arg.getType());
                  // If Reg use has no previous def
                  if (MBBDefRegs.find(find64BitSuperReg(Reg)) ==
                      MBBDefRegs.end())
                    addRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
                }

                // Check for return type and set return register as a
                // defined register
                Type *RetTy = CalledFunc->getReturnType();
                if (!RetTy->isVoidTy()) {
                  unsigned RetReg = X86::NoRegister;
                  unsigned RetRegSizeInBits = 0;
                  assert(RetTy->isIntOrPtrTy() &&
                         "Unhandled called function return type in function "
                         "prototype discovery");
                  if (RetTy->isPointerTy()) {
                    RetReg = X86::RAX;
                    RetRegSizeInBits = 64;
                  } else {
                    RetRegSizeInBits = RetTy->getPrimitiveSizeInBits();
                    switch (RetRegSizeInBits) {
                    case 64:
                      RetReg = X86::RAX;
                      break;
                    case 32:
                      RetReg = X86::EAX;
                      break;
                    case 16:
                      RetReg = X86::AX;
                      break;
                    case 8:
                      RetReg = X86::AL;
                      break;
                    default:
                      assert(false &&
                             "Unexpected size of called function return type "
                             "in function prototype discovery");
                    }
                  }
                  assert(RetReg != X86::NoRegister &&
                         "Failed to find return register in function prototype "
                         "discovery");
                  // Mark it as defined register
                  MBBDefRegs[find64BitSuperReg(RetReg)] = RetRegSizeInBits / 8;
                }
                // Record MBBNo as a block with tail call
                tailCallMBBNos.insert(MBBNo);
              }
            } else {
              assert(false && "Unhandled call or branch found during function "
                              "prototype discovery");
            }
          }
        } else {
          // First, look at use operands
          for (MachineOperand MO : MI.operands()) {
            if (!MO.isReg())
              continue;
            unsigned Reg = MO.getReg();
            if (!(llvm::X86::GR8RegClass.contains(Reg) ||
                  llvm::X86::GR16RegClass.contains(Reg) ||
                  llvm::X86::GR32RegClass.contains(Reg) ||
                  llvm::X86::GR64RegClass.contains(Reg)))
              continue;

            if (MO.isUse()) {
              // If Reg use has no previous def
              if (MBBDefRegs.find(find64BitSuperReg(Reg)) == MBBDefRegs.end())
                addRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
            }
          }
          // Next look at defs
          for (MachineOperand MO : MI.operands()) {
            if (!MO.isReg())
              continue;
            unsigned Reg = MO.getReg();
            if (!(llvm::X86::GR8RegClass.contains(Reg) ||
                  llvm::X86::GR16RegClass.contains(Reg) ||
                  llvm::X86::GR32RegClass.contains(Reg) ||
                  llvm::X86::GR64RegClass.contains(Reg)))
              continue;

            if (MO.isDef())
              // We need the last definition. Even if there is a previous
              // definition, it is correct to just over write the size
              // information.
              MBBDefRegs[find64BitSuperReg(Reg)] =
                  getPhysRegSizeInBits(Reg) / 8;
          }
        }
      }
      // Save the per-MBB define register definition information
      if (PerMBBDefinedPhysRegMap.find(MBBNo) !=
          PerMBBDefinedPhysRegMap.end()) {
        // Per-MBB reg def info is expected to exist only if this is not
        // the primary pass of the MBB.
        assert((!TraversedMBB.PrimaryPass) &&
               "Unexpected state of register definition information during "
               "function prototype discovery");
        // Clear the existing map to allow for adding new map
        PerMBBDefinedPhysRegMap.erase(MBBNo);
      }
      PerMBBDefinedPhysRegMap.emplace(MBBNo, MBBDefRegs);
    }

    // Use the first register usage list to form argument vector using
    // first argument register usage.
    buildFuncArgTypeVector(FunctionLiveInRegs, argTypeVector);
    // 2. Discover function return type
    returnType = getFunctionReturnType();

    // The Function object associated with current MachineFunction object
    // is only a place holder. It was created to facilitate creation of
    // MachineFunction object with a prototype void functionName(void).
    // The Module object contains this place-holder Function object in its
    // FunctionList. Since the return type and arguments are now
    // discovered, we need to replace this place holder Function object in
    // module with the correct Function object being created now.
    // 1. Get the current function name
    StringRef functionName = MF.getFunction().getName();
    Module *module = MR->getModule();
    // 2. Get the corresponding Function* registered in module
    Function *tempFunctionPtr = module->getFunction(functionName);
    assert(tempFunctionPtr != nullptr && "Function not found in module list");
    // 4. Delete the tempFunc from module list to allow for the creation
    // of
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

// Discover and return the type of return register definition in the block
// MBB. Return type is constructed based on the last definition of RAX (or
// its sub-register) in MBB. Only definitions of return register after the
// last call instruction, if one exists, in the block are considered to be
// indicative of return value set up.
Type *X86MachineInstructionRaiser::getReturnTypeFromMBB(MachineBasicBlock &MBB,
                                                        bool &HasCall) {
  Type *ReturnType = nullptr;
  HasCall = false;

  // Walk the block backwards
  for (MachineBasicBlock::const_reverse_instr_iterator I = MBB.instr_rbegin(),
                                                       E = MBB.instr_rend();
       I != E; I++) {
    // Do not inspect the last call instruction or instructions prior to
    // the last call instruction.
    if (I->isCall()) {
      HasCall = true;
      break;
    }

    // No need to inspect return instruction
    if (I->isReturn())
      continue;

    unsigned DefReg = X86::NoRegister;
    const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
    // Check if any of RAX, EAX, AX or AL are explicitly defined
    if (I->getDesc().getNumDefs() != 0) {
      const MachineOperand &MO = I->getOperand(0);
      if (MO.isReg()) {
        unsigned PReg = MO.getReg();
        if (!Register::isPhysicalRegister(PReg)) {
          continue;
        }
        // Check if PReg is any of the sub-registers of RAX (including
        // itself)
        for (MCSubRegIterator SubRegs(X86::RAX, TRI,
                                      /*IncludeSelf=*/true);
             (SubRegs.isValid() && DefReg == X86::NoRegister); ++SubRegs) {
          if (*SubRegs == PReg) {
            DefReg = *SubRegs;
            break;
          }
        }
      }
    }

    // If explicitly defined register is not a return register, check if
    // any of the sub-registers of RAX (including itself) is implicitly
    // defined.
    for (MCSubRegIterator SubRegs(X86::RAX, TRI, /*IncludeSelf=*/true);
         (SubRegs.isValid() && DefReg == X86::NoRegister); ++SubRegs) {
      if (hasExactImplicitDefOfPhysReg(*I, *SubRegs, TRI)) {
        DefReg = *SubRegs;
        break;
      }
    }

    // If the defined register is a return register
    if (DefReg != X86::NoRegister) {
      if (!Register::isPhysicalRegister(DefReg)) {
        continue;
      }
      if (ReturnType == nullptr) {
        ReturnType = getPhysRegType(DefReg);
        // Stop processing any further instructions as the return type is
        // found.
        break;
      }
    }
  }

  return ReturnType;
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
        llvm_unreachable("Unhandled register type encountered in binary");
      }
    }
  }

  // Build argument type vector that will be used to build FunctionType
  // while sanity checking arguments discovered
  for (int i = 1; i <= MaxArgNum; i++) {
    auto argIter = argNumTypeMap.find(i);
    if (argIter == argNumTypeMap.end()) {
      // Argument register not used. It is most likely optimized.
      // The argument is not used. Safe to consider it to be of 64-bit
      // type.
      ArgTyVec.push_back(Type::getInt64Ty(funcLLVMContext));
    } else
      ArgTyVec.push_back(argNumTypeMap.find(i)->second);
  }
  return true;
}

// If MI is a branch instruction return the MBB number corresponding to its
// target, if known. Return -1 in all other cases.
int64_t
X86MachineInstructionRaiser::getBranchTargetMBBNumber(const MachineInstr &MI) {
  int64_t TargetMBBNo = -1;

  if (MI.isBranch()) {
    const MCInstrDesc &MCID = MI.getDesc();

    if ((MI.getNumOperands() > 0) && MI.getOperand(0).isImm()) {
      // Only if this is a direct branch instruction with an immediate
      // offset
      if (X86II::isImmPCRel(MCID.TSFlags)) {
        // Get branch offset of the branch instruction
        const MachineOperand &MO = MI.getOperand(0);
        assert(MO.isImm() && "Expected immediate operand not found");
        int64_t BranchOffset = MO.getImm();
        MCInstRaiser *MCIR = getMCInstRaiser();
        // Get MCInst offset - the offset of machine instruction in the
        // binary
        assert(MCIR != nullptr && "MCInstRaiser not initialized");

        uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);
        int64_t BranchTargetOffset =
            MCInstOffset + MCIR->getMCInstSize(MCInstOffset) + BranchOffset;
        TargetMBBNo = MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset);
      }
    }
  }
  return TargetMBBNo;
}

// If MI is a call or tail call (i.e., branch to call target) return Function *
// corresponding to the callee. Return nullptr in all other cases.
Function *
X86MachineInstructionRaiser::getCalledFunction(const MachineInstr &MI) {
  Function *CalledFunc = nullptr;
  unsigned int Opcode = MI.getOpcode();

  switch (Opcode) {
  case X86::CALL64pcrel32:
  case X86::JMP_1:
  case X86::JMP_4: {

    const MCInstrDesc &MCID = MI.getDesc();
    assert(X86II::isImmPCRel(MCID.TSFlags) &&
           "PC-Relative control transfer expected");

    // Get target offset of the call instruction
    const MachineOperand &MO = MI.getOperand(0);
    assert(MO.isImm() && "Expected immediate operand not found");
    int64_t RelCallTargetOffset = MO.getImm();

    // Compute the MCInst index of the call target
    MCInstRaiser *MCIR = getMCInstRaiser();
    // Get MCInst offset of the corresponding call instruction in the
    // binary.
    uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);
    assert(MCIR != nullptr && "MCInstRaiser not initialized");
    uint64_t MCInstSize = MCIR->getMCInstSize(MCInstOffset);
    // First check if PC-relative call target embedded in the call
    // instruction can be used to get called function.
    int64_t CallTargetIndex = MCInstOffset + MR->getTextSectionAddress() +
                              MCInstSize + RelCallTargetOffset;
    // Get the function at index CalltargetIndex
    CalledFunc = MR->getRaisedFunctionAt(CallTargetIndex);

    // Search the called function from the excluded set of function
    // filter.
    if (CalledFunc == nullptr) {
      auto Filter = MR->getFunctionFilter();
      CalledFunc = Filter->findFunctionByIndex(
          MCInstOffset + RelCallTargetOffset + MCInstSize,
          FunctionFilter::FILTER_EXCLUDE);
    }

    // If not, use text section relocations to get the
    // call target function.
    if (CalledFunc == nullptr) {
      CalledFunc =
          MR->getCalledFunctionUsingTextReloc(MCInstOffset, MCInstSize);
    }
    // Look up the PLT to find called function
    if (CalledFunc == nullptr) {
      CalledFunc = getTargetFunctionAtPLTOffset(MI, CallTargetIndex);
    }
  } break;
  default:
    CalledFunc = nullptr;
  }
  return CalledFunc;
}
