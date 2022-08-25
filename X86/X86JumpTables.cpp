//===-- X86JumpTables.cpp ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of discovering jump tables in the
// source binary and raising them.
//
//===----------------------------------------------------------------------===//

#include "X86MachineInstructionRaiser.h"
#include "llvm-mctoll.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/BinaryByteStream.h"
#include "llvm/Support/Debug.h"
#include <X86InstrBuilder.h>
#include <X86Subtarget.h>

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

bool X86MachineInstructionRaiser::raiseMachineJumpTable() {
  // A vector to record MBBS that need be erased upon jump table creation.
  std::vector<MachineBasicBlock *> MBBsToBeErased;

  // Address of text section.
  int64_t TextSectionAddress = MR->getTextSectionAddress();
  MCInstRaiser *MCIR = getMCInstRaiser();

  // Get the MIs which potentially load the jumptable base address.
  for (MachineBasicBlock &JmpTblBaseCalcMBB : MF) {
    for (MachineBasicBlock::iterator CurMBBIter = JmpTblBaseCalcMBB.begin();
         CurMBBIter != JmpTblBaseCalcMBB.end(); CurMBBIter++) {
      MachineInstr &JmpTblBaseCalcMI = (*CurMBBIter);
      unsigned Opcode = JmpTblBaseCalcMI.getOpcode();
      auto InstKind = getInstructionKind(Opcode);
      // A vector of switch target MBBs
      std::vector<MachineBasicBlock *> JmpTgtMBBvec;
      // Physical destination register with the computed jump table base value.
      unsigned int JmpTblBaseReg = X86::NoRegister;
      // Find the MI LEA64r $rip and save offset of rip
      // This is typically generated in a shared library.
      if (Opcode == X86::LEA64r &&
          JmpTblBaseCalcMI.getOperand(1).getReg() == X86::RIP &&
          JmpTblBaseCalcMI.getOperand(4).isImm()) {
        uint32_t JmpOffset = JmpTblBaseCalcMI.getOperand(4).getImm();
        auto MCInstIndex = MCIR->getMCInstIndex(JmpTblBaseCalcMI);
        uint64_t MCInstSz = MCIR->getMCInstSize(MCInstIndex);
        // Calculate memory offset of the referenced offset.
        uint32_t JmpTblBaseMemAddress =
            TextSectionAddress + MCInstIndex + MCInstSz + JmpOffset;
        JmpTblBaseReg = JmpTblBaseCalcMI.getOperand(0).getReg();
        // Get the contents of the section with JmpTblBaseMemAddress
        const ELF64LEObjectFile *Elf64LEObjFile =
            dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
        assert(Elf64LEObjFile != nullptr &&
               "Only 64-bit ELF binaries supported at present.");
        const unsigned char *DataContent = nullptr;
        size_t DataSize = 0;
        size_t JmpTblEntryOffset = 0;
        // Find the section.
        for (section_iterator SecIter : Elf64LEObjFile->sections()) {
          uint64_t SecStart = SecIter->getAddress();
          uint64_t SecEnd = SecStart + SecIter->getSize();
          if ((SecStart <= JmpTblBaseMemAddress) &&
              (SecEnd >= JmpTblBaseMemAddress)) {
            StringRef Contents = unwrapOrError(
                SecIter->getContents(), MR->getObjectFile()->getFileName());
            DataContent =
                static_cast<const unsigned char *>(Contents.bytes_begin());
            DataSize = SecIter->getSize();
            JmpTblEntryOffset = JmpTblBaseMemAddress - SecStart;

            break;
          }
        }

        // Section with jump table base has no content.
        if (DataSize == 0)
          // Continue looking for MIs which potentially load a jumptable base
          // address.
          continue;

        while (JmpTblEntryOffset < DataSize) {
          // Get the 32-bit value at JmpTblEntryOffset in section data content.
          // This provides the offset value from JmpTblBaseMemAddress of the
          // corresponding jump table target. Add this offset to
          // JmpTblBaseMemAddress to get section address of jump target.

          uint32_t JmpTgtMemAddr = *(reinterpret_cast<const uint32_t *>(
                                       DataContent + JmpTblEntryOffset)) +
                                   JmpTblBaseMemAddress;

          // Get MBB corresponding to offset into text section of JmpTgtMemAddr
          auto MBBNo = MCIR->getMBBNumberOfMCInstOffset(
              JmpTgtMemAddr - TextSectionAddress, MF);

          // Continue reading 4-byte offsets from the section contents till
          // there is no valid MBB corresponding to jump target offset or
          // section end is reached.
          if (MBBNo == -1)
            break;

          MachineBasicBlock *MBB = MF.getBlockNumbered(MBBNo);
          JmpTgtMBBvec.push_back(MBB);
          // Attempt to get the next table entry value. Assuming that each
          // table entry is 4 bytes long. Stop before attempting to read past
          // Section data size.
          JmpTblEntryOffset += 4;
        }
      }
      // mov instruction of the kind mov offset(, IndxReg, Scale), Reg
      else {
        // Get index of memory reference in the instruction.
        int memoryRefOpIndex = getMemoryRefOpIndex(JmpTblBaseCalcMI);
        if ((InstKind == InstructionKind::MOV_FROM_MEM) ||
            (InstKind == InstructionKind::BRANCH_MEM_OP)) {
          assert((memoryRefOpIndex >= 0) && "Unexpected memory operand index");
          X86AddressMode memRef =
              llvm::getAddressFromInstr(&JmpTblBaseCalcMI, memoryRefOpIndex);
          if (memRef.Base.Reg == X86::NoRegister) {
            unsigned memReadTargetByteSz = getInstructionMemOpSize(Opcode);
            assert(memReadTargetByteSz > 0 &&
                   "Incorrect memory access size of instruction");
            int JmpTblBaseAddress = memRef.Disp;
            if (JmpTblBaseAddress > 0) {
              // This value should be an absolute offset into a rodata section.
              // Get the contents of the section with JmpTblBase
              const ELF64LEObjectFile *Elf64LEObjFile =
                  dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
              assert(Elf64LEObjFile != nullptr &&
                     "Only 64-bit ELF binaries supported at present.");
              StringRef Contents;
              JmpTblBaseReg = JmpTblBaseCalcMI.getOperand(0).getReg();
              size_t DataSize = 0;
              size_t JmpTblBaseOffset = 0;
              // Find the section.
              for (section_iterator SecIter : Elf64LEObjFile->sections()) {
                uint64_t SecStart = SecIter->getAddress();
                uint64_t SecEnd = SecStart + SecIter->getSize();
                // Potential JmpTblBase is in a data section
                // OK to cast to unsigned as JmpTblBase is > 0 at this point.
                if ((SecStart <= (unsigned)JmpTblBaseAddress) &&
                    (SecEnd >= (unsigned)JmpTblBaseAddress) &&
                    SecIter->isData()) {
                  Contents = unwrapOrError(SecIter->getContents(),
                                           MR->getObjectFile()->getFileName());
                  DataSize = SecIter->getSize();
                  JmpTblBaseOffset = JmpTblBaseAddress - SecStart;
                  break;
                }
              }

              // Section with jump table base has no content.
              if (DataSize == 0)
                // Continue looking for MIs which potentially load a jumptable
                // base address.
                continue;

              BinaryByteStream SectionContent(
                  Contents, llvm::support::endianness::little);
              size_t CurReadByteOffset = JmpTblBaseOffset;

              while (CurReadByteOffset < DataSize) {
                ArrayRef<uint8_t> v(memReadTargetByteSz);

                if (CurReadByteOffset + memReadTargetByteSz > DataSize)
                  break;

                Error EC = SectionContent.readBytes(CurReadByteOffset,
                                                    memReadTargetByteSz, v);
                // Eat the error; the section does not have jumptable data
                if (EC) {
                  handleAllErrors(std::move(EC),
                                  [&](const ErrorInfoBase &EI) {});
                  break;
                }

                uint64_t JmpTgtMemAddr =
                    llvm::support::endian::read64le(v.data());
                // get MBB corresponding to file offset into text section of
                // JmpTgtMemAddr
                auto MBBNo = MCIR->getMBBNumberOfMCInstOffset(
                    JmpTgtMemAddr - TextSectionAddress, MF);
                if (MBBNo != -1) {
                  MachineBasicBlock *MBB = MF.getBlockNumbered(MBBNo);
                  JmpTgtMBBvec.push_back(MBB);
                } else {
                  // Jump table entries are expected to be in a sequence. Once
                  // data that is different from a jump table entry is detected,
                  // stop looking for table entries.
                  break;
                }
                CurReadByteOffset += memReadTargetByteSz;
              }
            }
          }
        }
      }

      // If no potential jump target addresses were found the current
      // instruction does not compute jump table base.
      if (JmpTgtMBBvec.size() == 0) {
        continue;
      }

      // Check to verify the current  block - JmpTblBaseCalcMBB - terminates
      // with an indirect or an unconditional branch.
      bool BuildJumpTable = true;
      MachineInstr *JmpTblBaseCalcMBBTermInst = nullptr;
      for (auto &T : JmpTblBaseCalcMBB.terminators()) {
        if (T.isIndirectBranch() || T.isUnconditionalBranch()) {
          assert(JmpTblBaseCalcMBBTermInst == nullptr &&
                 "MachineBasicBlock with multiple branch terminators found");
          JmpTblBaseCalcMBBTermInst = &T;
        } else {
          BuildJumpTable = false;
          break;
        }
      }

      if (!BuildJumpTable)
        continue;

      if (InstKind == InstructionKind::MOV_FROM_MEM) {
        // Check to verify the current  block - JmpTblBaseCalcMBB - with the
        // instruction that potentially calculates jump table base does indeed
        // have register-based branch as the terminator and that register does
        // not get redefined by any intervening instruction.
        // NOTE: This check is not needed for branch with memory operand.
        unsigned SR = find64BitSuperReg(JmpTblBaseReg);

        for (MachineBasicBlock::const_instr_iterator instIter =
                 JmpTblBaseCalcMI.getNextNode()->getIterator();
             instIter != JmpTblBaseCalcMBB.end(); ++instIter) {
          for (auto O : instIter->defs()) {
            if (O.isReg()) {
              if (find64BitSuperReg(O.getReg()) == SR) {
                BuildJumpTable = false;
                break;
              }
            }
          }
          if (!BuildJumpTable)
            break;
        }

        if (!BuildJumpTable)
          continue;
      }

      assert(JmpTblBaseCalcMBBTermInst != nullptr &&
             "Branch instruction terminating basic block computing jump table "
             "base not found");

      // Find the MBB terminating with an indirect branch that would be changed
      // to switch instruction.
      MachineBasicBlock *SwitchMBB = nullptr;
      JumpTableInfo JmpTblInfo;

      if (JmpTblBaseCalcMBBTermInst->isUnconditionalBranch()) {
        assert(JmpTblBaseCalcMBB.succ_size() == 1 &&
               "Unexpected number of successors of a block terminating with "
               "unconditional branch");
        SwitchMBB = *(JmpTblBaseCalcMBB.succ_begin());
        MachineInstr &BranchInstr = *(SwitchMBB->getFirstTerminator());
        assert(BranchInstr.isIndirectBranch());
        // Delete the unconditional branch instruction.
        SwitchMBB->erase(BranchInstr);

        // Set default basic block in jump table info
        for (auto Pred : SwitchMBB->predecessors()) {
          if (Pred != &JmpTblBaseCalcMBB) {
            JmpTblInfo.df_MBB = Pred;
            break;
          }
        }
        // Set predecessor of current block as condition block of jump table
        // info
        JmpTblInfo.conditionMBB = *(SwitchMBB->pred_begin());
      } else if (JmpTblBaseCalcMBBTermInst->isIndirectBranch()) {
        assert((JmpTblBaseCalcMBB.pred_size() == 1) &&
               "Expect a single predecessor during jump table discovery");
        // With all the checks done, we can safely assume that this is a block
        // that computes the base of jumptables and delete it.
        MBBsToBeErased.push_back(&JmpTblBaseCalcMBB);

        // Construct jump table. Current block is the block which would
        // potentially contain the start of jump targets. If current block
        // has multiple predecessors this may not be a jump table. For now
        // assert this to discover potential situations in binaries. Change
        // the assert to and continue if the assumption is correct.
        SwitchMBB = *(JmpTblBaseCalcMBB.pred_begin());
        // Set default basic block in jump table info
        for (auto Succ : SwitchMBB->successors()) {
          if (Succ != &JmpTblBaseCalcMBB) {
            JmpTblInfo.df_MBB = Succ;
            break;
          }
        }

        // Predecessor block of current block (MBB) - which is jump table
        // block - is expected to have exactly two successors; one the current
        // block and the other which should become the default MBB for the
        // switch.
        assert((SwitchMBB->succ_size() == 2) &&
               "Unexpected number of successors of switch block");

        // Set predecessor of current block as condition block of jump table
        // info
        JmpTblInfo.conditionMBB = SwitchMBB;

        // Verify the branch instruction of SwitchMBB is a conditional
        // jmp that uses eflags. Go to the most recent instruction that
        // defines eflags. Remove that instruction as well as any subsequent
        // instruction that uses the register defined by that instruction.
        MachineInstr &BranchInstr = SwitchMBB->instr_back();
        std::vector<MachineInstr *> MBBInstrsToErase;
        if (BranchInstr.isConditionalBranch() &&
            BranchInstr.getDesc().hasImplicitUseOfPhysReg(X86::EFLAGS)) {
          // Delete the conditional branch instruction. The target of this
          // instruction is default block and fall-through is the block that
          // computes switch table base.
          SwitchMBB->erase(BranchInstr);
        } else
          llvm_unreachable("Conditional branch expected in switch basic block "
                           "during jump table discovery");
      } else
        llvm_unreachable("Unhandled case in jump table discovery");

      MachineJumpTableInfo *JTI =
          MF.getOrCreateJumpTableInfo(llvm::MachineJumpTableInfo::EK_Inline);
      JmpTblInfo.jtIdx = JTI->createJumpTableIndex(JmpTgtMBBvec);

      const X86Subtarget *STI = &MF.getSubtarget<X86Subtarget>();
      const X86InstrInfo *TII = STI->getInstrInfo();

      // Find the appropriate jump opcode based on the size of switch value
      BuildMI(SwitchMBB, DebugLoc(), TII->get(X86::JMP64r))
          .addJumpTableIndex(JmpTblInfo.jtIdx);
      jtList.push_back(JmpTblInfo);

      // Add jump table targets as successors of SwitchMBB.
      for (MachineBasicBlock *NewSucc : JmpTgtMBBvec) {
        if (!SwitchMBB->isSuccessor(NewSucc)) {
          SwitchMBB->addSuccessor(NewSucc);
        }
      }
    }
  }

  // Delete MBBs
  for (auto MBB : MBBsToBeErased) {
    // Remove MBB from the successors of all the predecessors of MBB
    for (auto Pred : MBB->predecessors())
      Pred->removeSuccessor(MBB);
    MBB->eraseFromParent();
  }

  LLVM_DEBUG(outs() << "CFG : After Raising Jump Tables\n");
  LLVM_DEBUG(MF.dump());
  return true;
}

// Return the Value * representing the value used to be searched in the given
// MachineBasicBlock with a jmp to jump-table.
Value *
X86MachineInstructionRaiser::getSwitchCompareValue(MachineBasicBlock &MBB) {
  Value *switchOnVal = nullptr;
  // Walk the basic block backwards to find the most recent
  // instruction that implicitly defines eflags.
  bool EflagsModifierFound = false;
  MachineBasicBlock::reverse_instr_iterator CurInstrIter = MBB.instr_rbegin();
  for (auto LastInstIter = MBB.instr_rend();
       ((CurInstrIter != LastInstIter) && (!EflagsModifierFound));
       ++CurInstrIter) {
    MachineInstr &curInst = *CurInstrIter;
    if (curInst.getDesc().hasImplicitDefOfPhysReg(X86::EFLAGS)) {
      EflagsModifierFound = true;
    }
  }
  assert(EflagsModifierFound &&
         "Failed to find eflags defining "
         "instruction while detecting switch compare value");
  // Note: decrement CurInstrIter to point to the eflags modifying
  // instruction.
  CurInstrIter--;
  // This instruction is either an compare or a sub instruction
  if (instrNameStartsWith(*CurInstrIter, "SUB") ||
      instrNameStartsWith(*CurInstrIter, "CMP")) {
    // This instruction is typically of the type sub reg, imm
    // used to set the EFLAGS. In this case, the switch value is reg.
    // A couple of sanity checks.
    assert((((CurInstrIter->getNumExplicitOperands() == 3) &&
             (CurInstrIter->getNumExplicitDefs() == 1)) ||
            ((CurInstrIter->getNumExplicitOperands() == 2) ||
             (CurInstrIter->getNumExplicitDefs() == 0))) &&
           "Unexpected number of operands of sub instruction found while "
           "detecting switch compare value");

    unsigned int cmpSrcReg = X86::NoRegister;

    if (CurInstrIter->getNumExplicitDefs() == 1) {
      const unsigned DestOpIndex = 0, UseOp1Index = 1, UseOp2Index = 2;
      const MachineOperand &SrcOp = CurInstrIter->getOperand(UseOp1Index);
      const MachineOperand &ImmOp = CurInstrIter->getOperand(UseOp2Index);
      assert(CurInstrIter->getOperand(DestOpIndex).isTied() &&
             (CurInstrIter->findTiedOperandIdx(DestOpIndex) == UseOp1Index) &&
             "Expect tied operand in neg instruction");
      assert(SrcOp.isReg() && ImmOp.isImm() &&
             "Unexpected types of operands of sub instruction found while "
             "detecting switch compare value");
      cmpSrcReg = SrcOp.getReg();
    } else if (CurInstrIter->getNumExplicitDefs() == 0) {
      const unsigned UseOp1Index = 0, UseOp2Index = 1;
      const MachineOperand &SrcOp = CurInstrIter->getOperand(UseOp1Index);
      const MachineOperand &ImmOp = CurInstrIter->getOperand(UseOp2Index);
      assert(SrcOp.isReg() && ImmOp.isImm() &&
             "Unexpected types of operands of sub instruction found while "
             "detecting switch compare value");
      cmpSrcReg = SrcOp.getReg();
    } else {
      assert(false && "Unexpected number of defs in compare instruction found "
                      "while determining switch compare value");
    }

    assert(Register::isPhysicalRegister(cmpSrcReg) &&
           "Unable to detect compare source register");
    Value *CmpVal = getRegOrArgValue(cmpSrcReg, MBB.getNumber());
    Instruction *CmpInst = dyn_cast<Instruction>(CmpVal);
    assert((CmpInst != nullptr) &&
           "Expect instruction while finding switch compare value");
    switchOnVal = CmpInst->getOperand(0);
    // If switchOnval is a cast value, it is most likely cast to match the
    // source of the compare instruction. Get to the value prior to casting.
    CastInst *castInst = dyn_cast<CastInst>(switchOnVal);
    while (castInst) {
      switchOnVal = castInst->getOperand(0);
      castInst = dyn_cast<CastInst>(switchOnVal);
    }
  } else if (instrNameStartsWith(*CurInstrIter, "XOR32")) {
    CurInstrIter--;
    const unsigned UseOp1Index = 1;
    const MachineOperand &SrcOp = CurInstrIter->getOperand(UseOp1Index);
    unsigned int cmpSrcReg = X86::NoRegister;
    cmpSrcReg = SrcOp.getReg();
    Value *CmpVal = getRegOrArgValue(cmpSrcReg, MBB.getNumber());
    Instruction *CmpInst = dyn_cast<Instruction>(CmpVal);
    assert((CmpInst != nullptr) &&
           "Expect instruction while finding switch compare value");
    switchOnVal = CmpInst->getOperand(0);
    // If switchOnval is a cast value, it is most likely cast to match the
    // source of the compare instruction. Get to the value prior to casting.
    CastInst *castInst = dyn_cast<CastInst>(switchOnVal);
    while (castInst) {
      switchOnVal = castInst->getOperand(0);
      castInst = dyn_cast<CastInst>(switchOnVal);
    }
  } else
    assert(false && "Unhandled EFLAGS modifying instruction found while "
                    "detecting switch compare value");

  return switchOnVal;
}

#undef DEBUG_TYPE
