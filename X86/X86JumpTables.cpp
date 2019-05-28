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

using namespace llvm;
using namespace mctoll;

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
      MachineInstr &JmpTblOffsetCalcMI = (*CurMBBIter);
      unsigned opcode = JmpTblOffsetCalcMI.getOpcode();
      // A vector of switch target MBBs
      std::vector<MachineBasicBlock *> JmpTgtMBBvec;
      // Find the MI LEA64r $rip and save offset of rip
      // This is typically generated in a shared library.
      if (opcode == X86::LEA64r &&
          // JmpTblOffsetCalcMI.getOperand(0).getReg() == X86::RAX &&
          JmpTblOffsetCalcMI.getOperand(1).getReg() == X86::RIP &&
          JmpTblOffsetCalcMI.getOperand(4).isImm()) {
        uint32_t JmpOffset = JmpTblOffsetCalcMI.getOperand(4).getImm();
        auto MCInstIndex = MCIR->getMCInstIndex(JmpTblOffsetCalcMI);
        uint64_t MCInstSz = MCIR->getMCInstSize(MCInstIndex);
        // Calculate memory offset of the referenced offset.
        uint32_t JmpTblBaseMemAddress =
            TextSectionAddress + MCInstIndex + MCInstSz + JmpOffset;

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
          // Get the 32-bit value at JmpTblEntryOffset in section data
          // content. This provides the offset value from JmpTblBaseMemAddress
          // of the corresponding jump table target. Add this offset to
          // JmpTblBaseMemAddress to get section address of jump target.

          uint32_t JmpTgtMemAddr = *(reinterpret_cast<const uint32_t *>(
                                       DataContent + JmpTblEntryOffset)) +
                                   JmpTblBaseMemAddress;

          // Get MBB corresponding to offset into text section of
          // JmpTgtMemAddr
          auto MBBNo = MCIR->getMBBNumberOfMCInstOffset(JmpTgtMemAddr -
                                                        TextSectionAddress);

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
      else if (getInstructionKind(opcode) == InstructionKind::MOV_FROM_MEM) {
        const MCInstrDesc &MIDesc = JmpTblOffsetCalcMI.getDesc();
        unsigned LoadOpIndex = 0;
        // Get index of memory reference in the instruction.
        int memoryRefOpIndex = getMemoryRefOpIndex(JmpTblOffsetCalcMI);
        assert(memoryRefOpIndex == 1 &&
               "Expect memory operand of a mem move instruction at index 1");
        assert(MIDesc.getNumDefs() == 1 &&
               JmpTblOffsetCalcMI.getOperand(LoadOpIndex).isReg() &&
               "Expect load operand register target");
        X86AddressMode memRef =
            llvm::getAddressFromInstr(&JmpTblOffsetCalcMI, memoryRefOpIndex);
        if (memRef.Base.Reg == X86::NoRegister) {
          const MachineOperand &LoadOp =
              JmpTblOffsetCalcMI.getOperand(LoadOpIndex);
          unsigned int LoadPReg = LoadOp.getReg();
          assert(
              TargetRegisterInfo::isPhysicalRegister(LoadPReg) &&
              "Expect destination to be a physical register in move from mem "
              "instruction");
          const TargetRegisterInfo *TRI =
              MF.getRegInfo().getTargetRegisterInfo();
          unsigned memReadTargetBitSz =
              TRI->getRegSizeInBits(LoadPReg, machineRegInfo);
          assert((memReadTargetBitSz % 8 == 0) &&
                 "Size of memory read not multiple bytes");
          unsigned memReadTargetByteSz = memReadTargetBitSz / 8;

          int JmpTblBaseAddress = memRef.Disp;
          if (JmpTblBaseAddress > 0) {
            // This value should be an absolute offset into a rodata section.
            // Get the contents of the section with JmpTblBase
            const ELF64LEObjectFile *Elf64LEObjFile =
                dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
            assert(Elf64LEObjFile != nullptr &&
                   "Only 64-bit ELF binaries supported at present.");
            StringRef Contents;
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

            BinaryByteStream SectionContent(Contents,
                                            llvm::support::endianness::little);
            size_t CurReadByteOffset = JmpTblBaseOffset;

            while (CurReadByteOffset < DataSize) {
              ArrayRef<uint8_t> v(memReadTargetByteSz);

              if (CurReadByteOffset + memReadTargetByteSz > DataSize)
                return true;

              Error EC = SectionContent.readBytes(CurReadByteOffset,
                                                  memReadTargetByteSz, v);
              // Eat the error; the section does not have jumptable data
              if (EC) {
                handleAllErrors(std::move(EC), [&](const ErrorInfoBase &EI) {});
                break;
              }

              uint64_t JmpTgtMemAddr =
                  llvm::support::endian::read64le(v.data());
              // get MBB corresponding to file offset into text section of
              // JmpTgtMemAddr
              auto MBBNo = MCIR->getMBBNumberOfMCInstOffset(JmpTgtMemAddr -
                                                            TextSectionAddress);
              if (MBBNo != -1) {
                MachineBasicBlock *MBB = MF.getBlockNumbered(MBBNo);
                JmpTgtMBBvec.push_back(MBB);
              }
              CurReadByteOffset += memReadTargetByteSz;
            }
          }
        }
      }

      // If no potential jump target addresses were found the current
      // instruction does not compute jump table base.
      if (JmpTgtMBBvec.size() == 0) {
        continue;
      }
      // Construct jump table. Current block is the block which would
      // potentially contain the start of jump targets. If current block
      // has multiple predecessors this may not be a jump table. For now
      // assert this to discover potential situations in binaries. Change
      // the assert to and continue if the assumption is correct.
      assert((JmpTblBaseCalcMBB.pred_size() == 1) &&
             "Expect a single predecessor during jump table discovery");
      MachineBasicBlock *JmpTblPredMBB = *(JmpTblBaseCalcMBB.pred_begin());
      // Predecessor block of current block (MBB) - which is jump table
      // block
      // - is expected to have exactly two successors; one the current
      // block and the other which should become the default MBB for the
      // switch.
      assert((JmpTblPredMBB->succ_size() == 2) &&
             "Unexpected number of successors of switch block");
      JumpTableInfo JmpTblInfo;
      // Set predecessor of current block as condition block of jump table
      // info
      JmpTblInfo.conditionMBB = JmpTblPredMBB;
      // Set default basic block in jump table info
      for (auto Succ : JmpTblPredMBB->successors()) {
        if (Succ != &JmpTblBaseCalcMBB) {
          JmpTblInfo.df_MBB = Succ;
          break;
        }
      }
      MachineJumpTableInfo *JTI =
          MF.getOrCreateJumpTableInfo(llvm::MachineJumpTableInfo::EK_Inline);
      JmpTblInfo.jtIdx = JTI->createJumpTableIndex(JmpTgtMBBvec);
      // Verify the branch instruction of JmpTblPredMBB is a conditional
      // jmp that uses eflags. Go to the most recent instruction that
      // defines eflags. Remove that instruction as well as any subsequent
      // instruction that uses the register defined by that instruction.
      MachineInstr &BranchInstr = JmpTblPredMBB->instr_back();
      std::vector<MachineInstr *> MBBInstrsToErase;
      if (BranchInstr.isConditionalBranch() &&
          BranchInstr.getDesc().hasImplicitUseOfPhysReg(X86::EFLAGS)) {
        // Walk the basic block backwards to find the most recent
        // instruction that implicitly defines eflags.
        bool EflagsModifierFound = false;
        MachineBasicBlock::reverse_instr_iterator CurInstrIter =
            JmpTblPredMBB->instr_rbegin();
        for (auto LastInstIter = JmpTblPredMBB->instr_rend();
             ((CurInstrIter != LastInstIter) && (!EflagsModifierFound));
             ++CurInstrIter) {
          MachineInstr &curInst = *CurInstrIter;
          if (curInst.getDesc().hasImplicitDefOfPhysReg(X86::EFLAGS)) {
            EflagsModifierFound = true;
          }
        }
        assert(EflagsModifierFound && "Failed to find eflags defining "
                                      "instruction during jump table "
                                      "extraction.");
        // Note: decrement CurInstrIter to point to the eflags modifying
        // instruction.
        CurInstrIter--;
        // Find the registers that the eflags modifying instruction
        // defines. Delete all instructions that uses them since we will
        // be deleting the eflags modifying instruction.
        MachineInstr &EflagsModInstr = *CurInstrIter;
        std::set<unsigned int> EflagsDefRegs;
        for (auto MO : EflagsModInstr.defs()) {
          // Create a set of all physical registers this instruction
          // defines.
          if (MO.isReg()) {
            unsigned int DefReg = MO.getReg();
            if (TargetRegisterInfo::isPhysicalRegister(DefReg)) {
              EflagsDefRegs.insert(find64BitSuperReg(DefReg));
            }
          }
        }

        // Add EflagsModInstr to the list of instructions to delete
        MBBInstrsToErase.push_back(&EflagsModInstr);

        MachineBasicBlock::iterator InstrEndIter = JmpTblPredMBB->instr_end();
        // Start walking the block instructions forward to identify
        // instructions that need be deleted.
        MachineBasicBlock::iterator InstrFwdIter =
            MachineBasicBlock::instr_iterator(CurInstrIter);
        // Find instructions that use any of the register in the set
        // EflagsDefRegs. Add it to a list of instructions that can be
        // deleted.
        while (InstrFwdIter != InstrEndIter) {
          MachineInstr &CurInstr = *InstrFwdIter;
          for (auto MO : CurInstr.uses()) {
            // Check if this use register is defined by EflagsModInstr
            if (MO.isReg()) {
              unsigned int UseReg = MO.getReg();
              if (TargetRegisterInfo::isPhysicalRegister(UseReg)) {
                unsigned SReg = (UseReg == X86::EFLAGS)
                                    ? UseReg
                                    : find64BitSuperReg(UseReg);
                if (EflagsDefRegs.find(SReg) != EflagsDefRegs.end()) {
                  MBBInstrsToErase.push_back(&CurInstr);
                  // No need to look for other register uses.
                  break;
                }
              }
            }
          }
          // If this instruction redefines any of the registers, remove
          // that register from EflagsDefRegs. Any instruction that uses
          // this redefined register and follows the current instruction,
          // should not be deleted.
          for (auto MO : CurInstr.defs()) {
            if (MO.isReg()) {
              unsigned int DefReg = MO.getReg();
              if (TargetRegisterInfo::isPhysicalRegister(DefReg)) {
                if (EflagsDefRegs.find(find64BitSuperReg(DefReg)) !=
                    EflagsDefRegs.end()) {
                  EflagsDefRegs.erase(DefReg);
                }
              }
            }
          }
          InstrFwdIter++;
        }
        // Finally add BranchInstr to the list of instructions to be
        // deleted
        MBBInstrsToErase.push_back(&BranchInstr);
        // Now delete the instructions
        for (auto MI : MBBInstrsToErase) {
          JmpTblPredMBB->erase(MI);
        }
      }

      const X86Subtarget *STI = &MF.getSubtarget<X86Subtarget>();
      const X86InstrInfo *TII = STI->getInstrInfo();

      MBBsToBeErased.push_back(&JmpTblBaseCalcMBB);
      BuildMI(JmpTblPredMBB, DebugLoc(), TII->get(X86::JMP64r))
          .addJumpTableIndex(JmpTblInfo.jtIdx);
      jtList.push_back(JmpTblInfo);
      // Add jump table targets as successors of JmpTblPredMBB.
      for (MachineBasicBlock *NewSucc : JmpTgtMBBvec) {
        if (!JmpTblPredMBB->isSuccessor(NewSucc)) {
          JmpTblPredMBB->addSuccessor(NewSucc);
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

  if (PrintPass) {
    outs() << "CFG : After Raising Jump Tables\n";
    MF.dump();
  }
  return true;
}

Instruction *
X86MachineInstructionRaiser::raiseConditonforJumpTable(MachineBasicBlock &mbb) {
  Instruction *cdi = nullptr;
  auto intr_conditon = mbbToBBMap.find(mbb.getNumber());
  BasicBlock *cd_bb = intr_conditon->second;

  // When the case id starts with 0, we use the LOAD instruction to
  // construct the condition value. Otherwise we use the ADD instruction.
  for (BasicBlock::iterator DI = cd_bb->begin(); DI != cd_bb->end(); DI++) {
    Instruction *ins = dyn_cast<Instruction>(DI);
    if (isa<LoadInst>(DI)) {
      cdi = ins;
    }

    if (cdi && (ins->getOpcode() == Instruction::Add)) {
      if (isa<ConstantInt>(ins->getOperand(1))) {
        ConstantInt *opr = dyn_cast<ConstantInt>(ins->getOperand(1));
        if (opr->isNegative()) {
          cdi = ins;
        }
      }
    }
  }
  return cdi;
}
