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

#include "IncludedFileInfo.h"
#include "Raiser/MachineFunctionRaiser.h"
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
using namespace llvm::mctoll;
using namespace llvm::mctoll::X86RegisterUtils;

// A convenience function that is slightly different from the LLVM API viz.,
// MCInstrDesc::hasImplicitDefOfPhysReg() which returns true if Reg or its
// sub-register is an implicit definition. In contrast, this function returns
// true only if Reg is an implicit definition.
static bool hasExactImplicitDefOfPhysReg(const MachineInstr &I, unsigned Reg,
                                         const MCRegisterInfo *MRI) {
  for (MCPhysReg ImpDef : I.getDesc().implicit_defs()) {
    if (ImpDef == Reg)
      return true;
  }
  return false;
}

// Return argument number associated with physical
// register PReg according to C calling convention.

int X86MachineInstructionRaiser::getArgumentNumber(unsigned PReg) {
  int Pos = -1;
  if (is8BitPhysReg(PReg)) {
    int Diff = std::distance(
        GPR64ArgRegs8Bit.begin(),
        std::find(GPR64ArgRegs8Bit.begin(), GPR64ArgRegs8Bit.end(), PReg));
    if ((Diff >= 0) && (Diff < (int)GPR64ArgRegs8Bit.size())) {
      Pos = Diff + 1;
    }
  } else if (is16BitPhysReg(PReg)) {
    int Diff = std::distance(
        GPR64ArgRegs16Bit.begin(),
        std::find(GPR64ArgRegs16Bit.begin(), GPR64ArgRegs16Bit.end(), PReg));
    if ((Diff >= 0) && (Diff < (int)GPR64ArgRegs16Bit.size())) {
      Pos = Diff + 1;
    }
  } else if (is32BitPhysReg(PReg)) {
    int Diff = std::distance(
        GPR64ArgRegs32Bit.begin(),
        std::find(GPR64ArgRegs32Bit.begin(), GPR64ArgRegs32Bit.end(), PReg));
    if ((Diff >= 0) && (Diff < (int)GPR64ArgRegs32Bit.size())) {
      Pos = Diff + 1;
    }
  } else if (is64BitPhysReg(PReg)) {
    int Diff = std::distance(
        GPR64ArgRegs64Bit.begin(),
        std::find(GPR64ArgRegs64Bit.begin(), GPR64ArgRegs64Bit.end(), PReg));
    if ((Diff >= 0) && (Diff < (int)GPR64ArgRegs64Bit.size())) {
      Pos = Diff + 1;
    }
  } else if (isSSE2Reg(PReg)) {
    int Diff = std::distance(
        SSEArgRegs64Bit.begin(),
        std::find(SSEArgRegs64Bit.begin(), SSEArgRegs64Bit.end(), PReg));
    if ((Diff >= 0) && (Diff < (int)SSEArgRegs64Bit.size())) {
      Pos = Diff + 1;
    }
  }
  return Pos;
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
  Type *ReturnType = nullptr;

  assert(x86TargetInfo.is64Bit() && "Only x86_64 binaries supported for now");

  // Find a return block. It is sufficient to get one of the return blocks to
  // find the return type. This type should be the same on any of the paths from
  // entry to any other return blocks.
  SmallVector<MachineBasicBlock *, 8> WorkList;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.isReturnBlock()) {
      // Push return block to ensure we look at the return block first.
      WorkList.push_back(&MBB);
      break;
    }
  }

  while (!WorkList.empty() && ReturnType == nullptr) {
    MachineBasicBlock *MBB = WorkList.pop_back_val();
    ReturnType = getReachingReturnType(*MBB);
  }

  // If return type is still not discovered, assume it to be void
  if (ReturnType == nullptr)
    ReturnType = Type::getVoidTy(MF.getFunction().getContext());

  return ReturnType;
}

// Construct prototype of the Function for the MachineFunction being raised.
FunctionType *X86MachineInstructionRaiser::getRaisedFunctionPrototype() {
  // Raise the jumptable
  raiseMachineJumpTable();

  if (RaisedFunction != nullptr)
    return RaisedFunction->getFunctionType();

  // Cleanup NOOP instructions from all MachineBasicBlocks
  deleteNOOPInstrMF();
  // Clean up any empty basic blocks
  unlinkEmptyMBBs();

  MF.getRegInfo().freezeReservedRegs(MF);
  std::vector<Type *> ArgTypeVector;

  // 1. Discover function arguments.
  // Function livein set will contain the actual registers that are
  // livein - not sub or super registers
  MCPhysRegSet FunctionLiveInRegs;
  // Set of registers defined in a block. These will be the 64-bit
  // super-register mapping to associated usage size.
  // NOTE: Using a map to record the access size instead of using the
  // LivePhysRegs type, since the binary code can define a sub-register
  // (e.g., $ecx) but use its super-register (e.g., $rcx). Such
  // situations can not be modeled using the LivePhysRegs::addReg API
  // since it only adds the reg and its sub-registers.
  MCPhysRegSizeMap MBBDefRegs;

  PerMBBDefinedPhysRegMap.clear();

  Type *DiscoveredRetType = nullptr;

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
    // handle blocks with terminator instruction that could potentially
    // result in a disconnected CFG - such as branch with register
    // target.
    MachineInstr &TermInst = MBB->instr_back();
    if (TermInst.isBranch()) {
      auto OpType = TermInst.getOperand(0).getType();
      assert(
          ((OpType == MachineOperand::MachineOperandType::MO_Immediate) ||
           (OpType == MachineOperand::MachineOperandType::MO_JumpTableIndex)) &&
          "Unexpected block terminator found");
    }

    // Union of defined registers of all predecessors
    for (auto *PredMBB : MBB->predecessors()) {
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
          Opc == X86::XOR8rr || Opc == X86::XORPDrr || Opc == X86::XORPSrr) {
        unsigned DestOpIndx = 0, SrcOp1Indx = 1, SrcOp2Indx = 2;
        const MachineOperand &DestOp = MI.getOperand(DestOpIndx);
        const MachineOperand &Use1Op = MI.getOperand(SrcOp1Indx);
        const MachineOperand &Use2Op = MI.getOperand(SrcOp2Indx);

        assert(Use1Op.isReg() && Use2Op.isReg() && DestOp.isReg() &&
               (MI.findTiedOperandIdx(SrcOp1Indx) == DestOpIndx) &&
               "Expecting register operands for xor instruction");

        // If the source regs are not the same
        if (Use1Op.getReg() != Use2Op.getReg()) {
          // If the source register has not been used before, add it to
          // the list of first use registers.
          Register UseReg = Use1Op.getReg();
          if (MBBDefRegs.find(find64BitSuperReg(UseReg)) == MBBDefRegs.end())
            addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);

          UseReg = Use2Op.getReg();
          if (MBBDefRegs.find(find64BitSuperReg(UseReg)) == MBBDefRegs.end())
            addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
        }

        // Add def reg to MBBDefRegs set
        Register DestReg = DestOp.getReg();
        // We need the last definition. Even if there is a previous definition,
        // it is correct to just overwrite the size information.
        MBBDefRegs[find64BitSuperReg(DestReg)] =
            getPhysRegSizeInBits(DestReg) / 8;
      } else if (MI.isCall() || MI.isUnconditionalBranch()) {
        // If this is an unconditional branch, check if it is a tail call.
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
              assert(MCIR != nullptr && "MCInstRaiser not initialized");

              // Get the (MCInst) offset of the instruction in the binary
              uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);
              int64_t BranchTargetOffset = MCInstOffset +
                                           MCIR->getMCInstSize(MCInstOffset) +
                                           BranchOffset;
              // This may be a tail call if there is no MBB corresponding to the
              // branch target offset.
              if (MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset, MF) ==
                  -1) {
                // It is a tail call only if there are no other instructions
                // after this unconditional branch instruction.
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
                unsigned Reg = getArgumentReg(ArgRegVecIndex++, Arg.getType());
                // If Reg use has no previous def
                if (MBBDefRegs.find(find64BitSuperReg(Reg)) == MBBDefRegs.end())
                  addRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
              }

              // Check for return type and set return register as a
              // defined register
              Type *RetTy = CalledFunc->getReturnType();
              if (!RetTy->isVoidTy()) {
                unsigned RetReg = X86::NoRegister;
                unsigned RetRegSizeInBits = 0;
                assert((RetTy->isIntOrPtrTy() || RetTy->isFloatingPointTy() ||
                        RetTy->isVectorTy()) &&
                       "Unhandled called function return type");
                if (RetTy->isPointerTy()) {
                  RetReg = X86::RAX;
                  RetRegSizeInBits = 64;
                } else if (RetTy->isIntegerTy()) {
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
                           "Unexpected size for called function return type");
                  }
                } else if (RetTy->isFloatingPointTy() || RetTy->isVectorTy()) {
                  RetRegSizeInBits = RetTy->getPrimitiveSizeInBits();
                  switch (RetRegSizeInBits) {
                  case 128:
                  case 64:
                  case 32:
                    RetReg = X86::XMM0;
                    break;
                  default:
                    llvm_unreachable("Unexpected size for called function "
                                     "return type");
                  }
                }
                assert(RetReg != X86::NoRegister &&
                       "Failed to find return register");
                // Mark it as defined register
                MBBDefRegs[find64BitSuperReg(RetReg)] = RetRegSizeInBits / 8;
              }

              if (IsTailCall)
                DiscoveredRetType = RetTy;
            }
          } else if (Opcode != X86::CALL64r && Opcode != X86::CALL64m) {
            // Not possible to statically determine the target of register-based
            // indirect call. Need to handle differently.
            assert(false && "Unhandled call or branch found");
          }
        }
      } else {
        // First, look at use operands
        for (MachineOperand MO : MI.operands()) {
          if (!MO.isReg())
            continue;

          Register Reg = MO.getReg();
          if (!(isGPReg(Reg) || isSSE2Reg(Reg)))
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

          Register Reg = MO.getReg();
          if (!(isGPReg(Reg) || isSSE2Reg(Reg)))
            continue;

          if (MO.isDef())
            // We need the last definition. Even if there is a previous
            // definition, it is correct to just over write the size
            // information.
            MBBDefRegs[find64BitSuperReg(Reg)] = getPhysRegSizeInBits(Reg) / 8;
        }
      }
    }

    // Save the per-MBB define register definition information
    if (PerMBBDefinedPhysRegMap.find(MBBNo) != PerMBBDefinedPhysRegMap.end()) {
      // Per-MBB reg def info is expected to exist only if this is not
      // the primary pass of the MBB.
      assert((!TraversedMBB.PrimaryPass) &&
             "Unexpected state of register definition information");
      // Clear the existing map to allow for adding new map
      PerMBBDefinedPhysRegMap.erase(MBBNo);
    }
    PerMBBDefinedPhysRegMap.emplace(MBBNo, MBBDefRegs);
  }

  // Use the first register usage list to form argument vector using
  // first argument register usage.
  buildFuncArgTypeVector(FunctionLiveInRegs, ArgTypeVector);
  // 2. Discover function return type
  Type *ReturnType = DiscoveredRetType != nullptr ? DiscoveredRetType
                                                  : getFunctionReturnType();
  if (ReturnType == nullptr)
    return nullptr;

  // The Function object associated with current MachineFunction object
  // is only a place holder. It was created to facilitate creation of
  // MachineFunction object with a prototype void functionName(void).
  // The Module object contains this place-holder Function object in its
  // FunctionList. Since the return type and arguments are now
  // discovered, we need to replace this place holder Function object in
  // module with the correct Function object being created now.

  // 1. Get the current function name
  StringRef FunctionName = MF.getFunction().getName();
  Module *Mod = MR->getModule();

  // 2. Get the corresponding Function* registered in module
  Function *TempFunctionPtr = Mod->getFunction(FunctionName);
  assert(TempFunctionPtr != nullptr && "Function not found in module list");

  // 4. Delete the tempFunc from module list to allow for the creation of the
  //    real function to add the correct one to FunctionList of the module.
  Mod->getFunctionList().remove(TempFunctionPtr);

  // 3. Create a function type using the discovered arguments and return value.
  FunctionType *FT =
      FunctionType::get(ReturnType, ArgTypeVector, false /* isVarArg*/);

  // 4. Create the real Function now that we have discovered the arguments.
  RaisedFunction =
      Function::Create(FT, GlobalValue::ExternalLinkage, FunctionName, Mod);

  // Set global linkage
  RaisedFunction->setLinkage(GlobalValue::ExternalLinkage);
  // Set C calling convention
  RaisedFunction->setCallingConv(CallingConv::C);
  // Set the function to be in the same linkage unit
  RaisedFunction->setDSOLocal(true);
  // TODO : Set other function attributes as needed.
  // Add argument names to the function.
  // Note: Call to arg_begin() calls Function::BuildLazyArguments()
  // to build the arguments.
  Function::arg_iterator ArgIt = RaisedFunction->arg_begin();
  unsigned NumFuncArgs = RaisedFunction->arg_size();
  StringRef Prefix("arg");
  // Set the name.
  for (unsigned Idx = 0; Idx < NumFuncArgs; ++Idx, ++ArgIt)
    ArgIt->setName(Prefix + std::to_string(Idx + 1));

  // Insert the map of raised function to tempFunctionPointer.
  const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
      RaisedFunction, TempFunctionPtr);

  return RaisedFunction->getFunctionType();
}

// Discover and return the type of return register (viz., RAX or its
// sub-register) definition that reaches MBB. Only definition of return register
// after the last call instruction or that found on a reverse traversal without
// encountering any call instruction, are considered to be indicative of return
// value set up.
Type *X86MachineInstructionRaiser::getReachingReturnType(
    const MachineBasicBlock &MBB) {
  bool HasCall = false;
  // Find return type in MBB
  Type *ReturnType = getReturnTypeFromMBB(MBB, HasCall);
  // If the MBB has no call instruction and return type is not found, traverse
  // up its predecessors to find the type of reaching definition of return
  // register.
  if (!HasCall) {
    if (ReturnType == nullptr) {
      // Initialize a bit vector tracking visited basic blocks
      BitVector BlockVisited(MF.getNumBlockIDs(), false);
      SmallVector<MachineBasicBlock *, 8> WorkList;
      Type *ReturnTypeOnPath = nullptr;

      for (auto *P : MBB.predecessors()) {
        WorkList.insert(WorkList.begin(), P);
      }

      while (!WorkList.empty() && !ReturnType) {
        MachineBasicBlock *PredMBB = WorkList.pop_back_val();
        int CurPredMBBNo = PredMBB->getNumber();
        if (!BlockVisited[CurPredMBBNo]) {
          // Mark block as visited
          BlockVisited.set(CurPredMBBNo);
          // Get function return type from MBB
          ReturnTypeOnPath = getReturnTypeFromMBB(*PredMBB, HasCall);
          // If PredMBB has no call and has no return  register definition,
          // continue traversal.
          if (!HasCall && ReturnTypeOnPath == nullptr) {
            // If PredMBB is the entry block and return type is not found, it
            // implies that there is at least one path that doesn't set return
            // register. Hence, there is no further need for further traversal.
            if (PredMBB->isEntryBlock()) {
              ReturnType = nullptr;
              break;
            }
            // Continue traversal
            for (auto *Pred : PredMBB->predecessors()) {
              if (!BlockVisited[Pred->getNumber()])
                WorkList.insert(WorkList.begin(), Pred);
            }
          } else {
            // ReturnTypeOnPath is found
            if (ReturnTypeOnPath) {
              // Ensure it is the same as any found along other reverse
              // traversals.
              if (ReturnType)
                assert(ReturnType == ReturnTypeOnPath);
              else
                // Return type found on this traversal
                ReturnType = ReturnTypeOnPath;
            }
          }
        }
      }
    }
  }

  return ReturnType;
}

// Discover and return the type of return register definition in the block
// MBB. Return type is constructed based on the last definition of RAX (or
// its sub-register) in MBB. Only definitions of return register after the
// last call instruction, if one exists, in the block are considered to be
// indicative of return value set up.
Type *
X86MachineInstructionRaiser::getReturnTypeFromMBB(const MachineBasicBlock &MBB,
                                                  bool &HasCall) {
  LLVMContext &Ctx(MF.getFunction().getContext());
  Type *ReturnType = nullptr;
  HasCall = false;

  // Walk the block backwards
  for (MachineBasicBlock::const_reverse_instr_iterator I = MBB.instr_rbegin(),
                                                       E = MBB.instr_rend();
       I != E; I++) {
    // No need to inspect instructions prior to the last call instruction since
    // the function prototype will indicate if the called function has a return
    // value. The return type of the called function is the return type of this
    // function.
    if (I->isCall()) {
      Function *CalledFunc = getCalledFunction(*I);
      HasCall = true;
      // Raised function prototype of the called function may not yet be
      // constructed. In that case, consider return type to be void.
      ReturnType =
          (CalledFunc == nullptr)
              ? nullptr /* Type::getVoidTy(MF.getFunction().getContext()) */
              : CalledFunc->getReturnType();
      break;
    }

    if (ReturnType)
      return ReturnType;

    // No need to inspect return instruction
    if (I->isReturn())
      continue;

    // No need to inspect padding instructions. ld uses nop and lld uses int3
    // for alignment padding in text section.
    auto Opcode = I->getOpcode();
    if (isNoop(Opcode) || (Opcode == X86::INT3))
      continue;

    unsigned DefReg = X86::NoRegister;
    const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
    // Check if any of RAX, EAX, AX or AL are explicitly defined
    if (I->getDesc().getNumDefs() != 0) {
      const MachineOperand &MO = I->getOperand(0);
      if (MO.isReg()) {
        Register PReg = MO.getReg();
        if (!Register::isPhysicalRegister(PReg))
          continue;

        // Check if PReg is any of the sub-registers of RAX (including itself)
        for (MCSubRegIterator SubRegs(X86::RAX, TRI,
                                      /*IncludeSelf=*/true);
             (SubRegs.isValid() && DefReg == X86::NoRegister); ++SubRegs) {
          if (*SubRegs == PReg.asMCReg()) {
            DefReg = *SubRegs;
            break;
          }
        }
        if (DefReg == X86::NoRegister && PReg == X86::XMM0) {
          DefReg = X86::XMM0;
          ReturnType = getRaisedValues()->getSSEInstructionType(
              *I, 128 /* Size of XMM0 */, Ctx);
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

    if (DefReg == X86::NoRegister &&
        hasExactImplicitDefOfPhysReg(*I, X86::XMM0, TRI)) {
      DefReg = X86::XMM0;
      ReturnType = getRaisedValues()->getSSEInstructionType(
          *I, 128 /* Size of XMM0 */, Ctx);
    }

    // If the defined register is a return register
    if (DefReg != X86::NoRegister) {
      if (!Register::isPhysicalRegister(DefReg))
        continue;

      if (ReturnType == nullptr) {
        ReturnType = getPhysRegType(DefReg);
        // Stop processing any further instructions as the return type is found.
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
  std::map<unsigned int, Type *> ArgNumTypeMap;
  std::map<unsigned int, Type *> SSEArgNumTypeMap;
  llvm::LLVMContext &Ctx = MF.getFunction().getContext();
  int MaxGPArgNum = 0;
  int MaxSSEArgNum = 0;

  for (MCPhysReg PReg : PhysRegs) {
    // If Reg is an argument register per C standard calling convention
    // construct function argument.
    int ArgNum = getArgumentNumber(PReg);
    if (ArgNum > 0) {

      if (isGPReg(PReg)) {
        if (ArgNum > MaxGPArgNum)
          MaxGPArgNum = ArgNum;

        // Make sure each argument position is discovered only once
        assert(ArgNumTypeMap.find(ArgNum) == ArgNumTypeMap.end());
        if (is8BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt8Ty(Ctx)));
        } else if (is16BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt16Ty(Ctx)));
        } else if (is32BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt32Ty(Ctx)));
        } else if (is64BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt64Ty(Ctx)));
        }
      } else if (isSSE2Reg(PReg)) {
        if (ArgNum > MaxSSEArgNum)
          MaxSSEArgNum = ArgNum;

        // Make sure each argument position is discovered only once
        assert(SSEArgNumTypeMap.find(ArgNum) == SSEArgNumTypeMap.end());
        SSEArgNumTypeMap.insert(
            std::make_pair(ArgNum, Type::getDoubleTy(Ctx)));
      } else {
        outs() << x86RegisterInfo->getRegAsmName(PReg) << "\n";
        llvm_unreachable("Unhandled register type encountered in binary");
      }
    }
  }

  // Build argument type vector that will be used to build FunctionType
  // while sanity checking arguments discovered
  for (int Idx = 1; Idx <= MaxGPArgNum; Idx++) {
    auto ArgIter = ArgNumTypeMap.find(Idx);
    if (ArgIter == ArgNumTypeMap.end()) {
      // Argument register not used. It is most likely optimized.
      // The argument is not used. Safe to consider it to be of 64-bit
      // type.
      ArgTyVec.push_back(Type::getInt64Ty(Ctx));
    } else
      ArgTyVec.push_back(ArgNumTypeMap.find(Idx)->second);
  }
  // TODO: for now we just assume that SSE registers are always the last
  // arguments This may work when compiling to X86 using the System V ABI, not
  // necessarily for other ABIs.
  for (int Idx = 1; Idx <= MaxSSEArgNum; Idx++) {
    auto ArgIter = SSEArgNumTypeMap.find(Idx);
    if (ArgIter == SSEArgNumTypeMap.end()) {
      ArgTyVec.push_back(Type::getDoubleTy(Ctx));
    } else {
      ArgTyVec.push_back(ArgIter->second);
    }
  }
  return true;
}

// If MI is a branch instruction return the MBB number corresponding to its
// target, if known. Return -1 in all other cases.
int64_t
X86MachineInstructionRaiser::getBranchTargetMBBNumber(const MachineInstr &MI) {
  int64_t TargetMBBNo = -1;

  if (!MI.isBranch())
    return TargetMBBNo;

  const MCInstrDesc &MCID = MI.getDesc();
  if ((MI.getNumOperands() > 0) && MI.getOperand(0).isImm()) {
    // Only if this is a direct branch instruction with an immediate offset
    if (X86II::isImmPCRel(MCID.TSFlags)) {
      // Get branch offset of the branch instruction
      const MachineOperand &MO = MI.getOperand(0);
      assert(MO.isImm() && "Expected immediate operand not found");
      int64_t BranchOffset = MO.getImm();
      MCInstRaiser *MCIR = getMCInstRaiser();
      // Get MCInst offset - the offset of machine instruction in the binary
      assert(MCIR != nullptr && "MCInstRaiser not initialized");

      uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);
      int64_t BranchTargetOffset =
          MCInstOffset + MCIR->getMCInstSize(MCInstOffset) + BranchOffset;
      TargetMBBNo = MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset, MF);
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
    assert(MCIR != nullptr && "MCInstRaiser not initialized");
    // Get MCInst offset of the corresponding call instruction in the binary.
    uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);
    uint64_t MCInstSize = MCIR->getMCInstSize(MCInstOffset);
    // First check if PC-relative call target embedded in the call
    // instruction can be used to get called function.
    int64_t CallTargetIndex = MCInstOffset + MR->getTextSectionAddress() +
                              MCInstSize + RelCallTargetOffset;
    // Get the function at index CalltargetIndex
    CalledFunc = MR->getRaisedFunctionAt(CallTargetIndex);

    // Search the called function from the excluded set of function filter.
    if (CalledFunc == nullptr) {
      auto *Filter = MR->getFunctionFilter();
      CalledFunc = Filter->findFunctionByIndex(
          MCInstOffset + RelCallTargetOffset + MCInstSize,
          FunctionFilter::FILTER_EXCLUDE);
    }

    // If not, use text section relocations to get the
    // call target function.
    if (CalledFunc == nullptr)
      CalledFunc =
          MR->getCalledFunctionUsingTextReloc(MCInstOffset, MCInstSize);

    // Look up the PLT to find called function
    if (CalledFunc == nullptr)
      CalledFunc = getTargetFunctionAtPLTOffset(MI, CallTargetIndex);
  } break;
  }

  return CalledFunc;
}
