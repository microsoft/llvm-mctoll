//===-- X86MachineInstructionRaiserUtils.cpp ---------------------*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the various utility/helper functions declared in
// X86MachineInstructionRaiser class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ExternalFunctions.h"
#include "InstMetadata.h"
#include "X86MachineInstructionRaiser.h"
#include "X86RaisedValueTracker.h"
#include "X86RegisterUtils.h"
#include "llvm-mctoll.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include <X86InstrBuilder.h>
#include <X86Subtarget.h>

using namespace llvm;
using namespace mctoll;
using namespace X86RegisterUtils;

// Delete noop instructions
bool X86MachineInstructionRaiser::deleteNOOPInstrMI(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI) {
  MachineInstr &MI = *MBBI;
  if (isNoop(MI.getOpcode())) {
    MBB.remove(&MI);
    return true;
  }
  return false;
}

bool X86MachineInstructionRaiser::deleteNOOPInstrMF() {
  bool modified = false;
  for (MachineBasicBlock &MBB : MF) {
    // MBBI may be invalidated by the raising operation.
    MachineBasicBlock::iterator MBBI = MBB.begin(), E = MBB.end();
    while (MBBI != E) {
      MachineBasicBlock::iterator NMBBI = std::next(MBBI);
      modified |= deleteNOOPInstrMI(MBB, MBBI);
      MBBI = NMBBI;
    }
  }
  return modified;
}

bool X86MachineInstructionRaiser::unlinkEmptyMBBs() {
  bool modified = false;
  std::set<unsigned> EmptyMBBNos;
  // Collect empty basic block numbers
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty())
      EmptyMBBNos.insert(MBB.getNumber());
  }
  // Get rid of any empty MachineBasicBlocks
  if (!EmptyMBBNos.empty()) {
    for (auto MBBNo : EmptyMBBNos) {
      MachineBasicBlock *DelMBB = MF.getBlockNumbered(MBBNo);
      // Transfer all successors of DelMBB as successors of each of the
      // predecessors of DelMBB.
      if (DelMBB->pred_size() > 0) {
        for (auto DelMBBPred : DelMBB->predecessors()) {
          DelMBBPred->transferSuccessors(DelMBB);
        }
      } else {
        // If DelMBB does not have any predecessors, successors of DelMBB would
        // not be deleted since transferAllSuccessors will not be called. So, we
        // need to explicitly delete all successors of DelMBB.
        for (auto DelMBBSucc : DelMBB->successors()) {
          DelMBB->removeSuccessor(DelMBBSucc);
        }
      }
      // Do not delete DelMBB
    }
    modified = true;
  }
  return modified;
}

// Return the Type of the physical register.
Type *X86MachineInstructionRaiser::getPhysRegType(unsigned int PReg) {
  LLVMContext &Ctx(MF.getFunction().getContext());

  if (is64BitPhysReg(PReg))
    return Type::getInt64Ty(Ctx);
  if (is32BitPhysReg(PReg))
    return Type::getInt32Ty(Ctx);
  if (is16BitPhysReg(PReg))
    return Type::getInt16Ty(Ctx);
  if (is8BitPhysReg(PReg))
    return Type::getInt8Ty(Ctx);

  assert(false && "Immediate operand of unknown size");
  return nullptr;
}

Type *X86MachineInstructionRaiser::getImmOperandType(const MachineInstr &MI,
                                                     unsigned int OpIndex) {
  LLVMContext &Ctx(MI.getMF()->getFunction().getContext());
  MachineOperand Op = MI.getOperand(OpIndex);
  assert(Op.isImm() && "Attempt to get size of non-immediate operand");

  uint8_t ImmSize = X86II::getSizeOfImm(MI.getDesc().TSFlags);
  switch (ImmSize) {
  case 8:
    return Type::getInt64Ty(Ctx);
  case 4:
    return Type::getInt32Ty(Ctx);
  case 2:
    return Type::getInt16Ty(Ctx);
  case 1:
    return Type::getInt8Ty(Ctx);
  default:
    llvm_unreachable("Immediate operand of unknown size");
  }
}

uint8_t
X86MachineInstructionRaiser::getPhysRegOperandSize(const MachineInstr &MI,
                                                   unsigned int OpIndex) {
  MachineOperand Op = MI.getOperand(OpIndex);
  assert(Op.isReg() && "Attempt to get size of non-register operand");
  return (getPhysRegSizeInBits(Op.getReg()) / sizeof(uint64_t));
}

Type *X86MachineInstructionRaiser::getPhysRegOperandType(const MachineInstr &MI,
                                                         unsigned int OpIndex) {
  MachineOperand Op = MI.getOperand(OpIndex);
  assert(Op.isReg() && "Attempt to get type of non-register operand");

  LLVMContext &Ctx(MI.getMF()->getFunction().getContext());
  return Type::getIntNTy(Ctx, getPhysRegSizeInBits(Op.getReg()));
}

bool X86MachineInstructionRaiser::isPushToStack(const MachineInstr &MI) const {
  return instrNameStartsWith(MI, "PUSH") || instrNameStartsWith(MI, "ENTER");
}

bool X86MachineInstructionRaiser::isPopFromStack(const MachineInstr &MI) const {
  return instrNameStartsWith(MI, "POP") || instrNameStartsWith(MI, "LEAVE");
}

bool X86MachineInstructionRaiser::isEffectiveAddrValue(Value *Val) {
  if (isa<LoadInst>(Val))
    return true;

  // A call may return a pointer that can be considered an effective address.
  if (isa<CallInst>(Val))
    return true;

  // An instruction that casts a pointer value may be considered as an effective
  // address.
  if (isa<CastInst>(Val)) {
    return (dyn_cast<CastInst>(Val)->getSrcTy()->isPointerTy());
  }

  if (isa<BinaryOperator>(Val)) {
    BinaryOperator *BinOpVal = dyn_cast<BinaryOperator>(Val);
    if (BinOpVal->isBinaryOp(BinaryOperator::Add) ||
        BinOpVal->isBinaryOp(BinaryOperator::Mul)) {
      return true;
    }
  }

  // Consider an argument of integer type to be an address value type.
  if (Val->getType()->isIntegerTy() && (Val->getName().startswith("arg")))
    return true;

  return false;
}

bool X86MachineInstructionRaiser::recordDefsToPromote(unsigned PhysReg,
                                                      unsigned MBBNo,
                                                      Value *Alloca) {
  reachingDefsToPromote.insert(std::make_tuple(PhysReg, MBBNo, Alloca));
  return true;
}

// Return true if MBB has a definition of PhysReg in the instruction range
// [StopInst, StartMI) where StopInst is the last instance of instruction with
// the opcode property StopAtInstProp. For example, if StopAtInstProp is
// MCID::Call, this function returns true if PhysReg is defined in the range
// [LCI, StartInst) where LCI is the last call instruction in MBB.
//
// If StartMI is nullptr, the range searched in [StopInst, BlockEndInst].
bool X86MachineInstructionRaiser::hasPhysRegDefInBlock(
    int PhysReg, const MachineInstr *StartMI, const MachineBasicBlock *MBB,
    unsigned StopAtInstProp, bool &HasStopInst) {
  // Walk backwards starting from the instruction before StartMI
  HasStopInst = false; // default value
  unsigned SuperReg = find64BitSuperReg(PhysReg);
  auto InstIter = (StartMI == nullptr) ? MBB->rend() : StartMI->getReverseIterator();
  for (const MachineInstr &MI : make_range(++InstIter, MBB->rend())) {
    // Stop after the instruction with the specified property in the block
    if (MI.hasProperty(StopAtInstProp)) {
      HasStopInst = true;
      break;
    }

    // If the instruction has a define
    if (MI.getNumDefs() > 0) {
      for (auto MO : MI.defs()) {
        // If the define operand is a register
        if (MO.isReg()) {
          unsigned MOReg = MO.getReg();
          if (Register::isPhysicalRegister(MOReg)) {
            if (SuperReg == find64BitSuperReg(MOReg))
              return true;
          }
        }
      }
    }
  }

  return false;
}

// FPU Access functions
void X86MachineInstructionRaiser::FPURegisterStackPush(Value *val) {
  assert(val->getType()->isFloatingPointTy() &&
         "Attempt to push non-FP type value on FPU register stack");
  assert((FPUStack.TOP < FPUSTACK_SZ) && (FPUStack.TOP >= 0) &&
         "Incorrect initial FPU Register Stack top in push");

  int8_t PushIndex = (FPUSTACK_SZ + FPUStack.TOP - 1) % FPUSTACK_SZ;

  assert((PushIndex < FPUSTACK_SZ) && (PushIndex >= 0) &&
         "Incorrect FPU Register Stack index computed in push");
  FPUStack.Regs[PushIndex] = val;
  FPUStack.TOP = PushIndex;
}

void X86MachineInstructionRaiser::FPURegisterStackPop() {
  assert((FPUStack.TOP < FPUSTACK_SZ) && (FPUStack.TOP >= 0) &&
         "Incorrect initial FPU Register Stack top in pop");

  int8_t PostPopIndex = (FPUSTACK_SZ + FPUStack.TOP + 1) % FPUSTACK_SZ;

  assert((PostPopIndex < FPUSTACK_SZ) && (PostPopIndex >= 0) &&
         "Incorrect FPU Register Stack index computed in pop");
  // Clear the value at current TOP
  FPUStack.Regs[FPUStack.TOP] = nullptr;
  // Adjust TOP value
  FPUStack.TOP = PostPopIndex;
}

// Get value at index
Value *X86MachineInstructionRaiser::FPURegisterStackGetValueAt(int8_t index) {
  assert((FPUStack.TOP < FPUSTACK_SZ) && (FPUStack.TOP >= 0) &&
         "Incorrect initial FPU Register Stack top in FPU register access");

  int8_t AccessIndex = (FPUSTACK_SZ + FPUStack.TOP + index) % FPUSTACK_SZ;

  assert((AccessIndex < FPUSTACK_SZ) && (AccessIndex >= 0) &&
         "Incorrect FPU Register Stack index computed in FPU register access");

  return FPUStack.Regs[AccessIndex];
}

// Set value at index to val
void X86MachineInstructionRaiser::FPURegisterStackSetValueAt(int8_t index,
                                                             Value *val) {
  assert(val->getType()->isFloatingPointTy() &&
         "Attempt to insert non-FP type value in FPU register stack");
  assert((FPUStack.TOP < FPUSTACK_SZ) && (FPUStack.TOP >= 0) &&
         "Incorrect initial FPU Register Stack top in FPU register access");

  int8_t AccessIndex = (FPUSTACK_SZ + FPUStack.TOP + index) % FPUSTACK_SZ;

  assert((AccessIndex < FPUSTACK_SZ) && (AccessIndex >= 0) &&
         "Incorrect FPU Register Stack index computed in FPU register access");

  FPUStack.Regs[AccessIndex] = val;
}

Value *X86MachineInstructionRaiser::FPURegisterStackTop() {
  return FPURegisterStackGetValueAt(0);
}

unsigned int
X86MachineInstructionRaiser::find64BitSuperReg(unsigned int PhysReg) {

  // No super register for 0 register
  if (PhysReg == X86::NoRegister) {
    return X86::NoRegister;
  }

  // Nothing to do if PhysReg is one of EFLAG bits, FPSW, FPCW
  if (isEflagBit(PhysReg))
    return PhysReg;

  if ((PhysReg == X86::FPSW) || (PhysReg == X86::FPCW)) {
    return PhysReg;
  }

  // Nothing to do if PhysReg is a 64-bit register.
  if (is64BitPhysReg(PhysReg)) {
    return PhysReg;
  }

  // The return value.
  unsigned int SuperReg;

  // Did we find it.
  bool SuperRegFound = false;

  for (MCSuperRegIterator SuperRegsIter(PhysReg, x86RegisterInfo);
       SuperRegsIter.isValid(); ++SuperRegsIter) {
    SuperReg = *SuperRegsIter;
    if (is64BitPhysReg(SuperReg)) {
      assert(SuperRegFound != true && "Expect only one 64-bit super register");
      SuperRegFound = true;
    }
  }

  assert(SuperRegFound && "Super register not found");
  return SuperReg;
}

BasicBlock *
X86MachineInstructionRaiser::getRaisedBasicBlock(const MachineBasicBlock *MBB) {
  // Get the BasicBlock corresponding to MachineBasicBlock MBB
  auto MapIter = mbbToBBMap.find(MBB->getNumber());
  assert(MapIter != mbbToBBMap.end() &&
         "Failed to find BasicBlock corresponding to MachineBasicBlock");
  BasicBlock *RaisedBB = MapIter->second;
  assert((RaisedBB != nullptr) &&
         "Encountered null BasicBlock corresponding to MachineBasicBlock");
  return RaisedBB;
}

// Return a Value representing stack-allocated object
Value *X86MachineInstructionRaiser::createPCRelativeAccesssValue(
    const MachineInstr &MI) {
  Value *MemrefValue = nullptr;
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  // Should have found the index of the memory reference operand
  assert(MemoryRefOpIndex != -1 &&
         "Unable to find memory reference operand of a load/store instruction");
  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);

  // LLVM represents memory operands using 5 operands
  //    viz., <opcode> BaseReg, ScaleAmt, IndexReg, Disp, Segment, ...
  // The disassembly in AT&T syntax is shown as
  //      Segment:Disp(BaseReg, IndexReg, ScaleAmt).
  // or as
  //      Segment:[BaseReg + Disp + IndexReg * ScaleAmt]
  // in Intel syntax.
  // effective address is calculated to be Segment:[BaseReg + IndexReg *
  // ScaleAmt + Disp] Segment is typically X86::NoRegister.

  assert(MI.getOperand(MemoryRefOpIndex + X86::AddrSegmentReg).getReg() ==
             X86::NoRegister &&
         "Expect no segment register");

  // Construct non-stack memory referencing value
  unsigned BaseReg = MemRef.Base.Reg;
  unsigned IndexReg = MemRef.IndexReg;
  unsigned ScaleAmt = MemRef.Scale;
  int Disp = MemRef.Disp;
  const MachineOperand &SegRegOperand =
      MI.getOperand(MemoryRefOpIndex + X86::AddrSegmentReg);
  // For now, we assume default segment DS (and hence no specification of
  // Segment register.
  assert(SegRegOperand.isReg() && (SegRegOperand.getReg() == X86::NoRegister) &&
         "Unhandled memory reference instruction with non-zero segment "
         "register");
  // Also assume that PC-relative addressing does not involve index register
  assert(IndexReg == X86::NoRegister &&
         "Unhandled index register in PC-relative memory addressing "
         "instruction");
  assert(ScaleAmt == 1 && "Unhandled value of scale amount in PC-relative "
                          "memory addressing instruction");

  // Non-stack memory address is supported by this function.
  uint64_t BaseSupReg = find64BitSuperReg(BaseReg);
  assert(((BaseSupReg == X86::RIP) || (BaseSupReg == X86::NoRegister)) &&
         "Base register that is not PC encountered in memory access "
         "instruction");

  // 1. Get the text section address
  int64_t TextSectionAddress = MR->getTextSectionAddress();

  assert(TextSectionAddress >= 0 && "Failed to find text section address");

  // 2. Get MCInst offset - the offset of machine instruction in the binary
  // and instruction size
  MCInstRaiser *MCIRaiser = getMCInstRaiser();
  uint64_t MCInstOffset = MCIRaiser->getMCInstIndex(MI);
  uint64_t MCInstSz = MCIRaiser->getMCInstSize(MCInstOffset);

  // 3. Compute the PC-relative offset.

  const ELF64LEObjectFile *Elf64LEObjFile =
      dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
  assert(Elf64LEObjFile != nullptr &&
         "Only 64-bit ELF binaries supported at present.");

  auto EType = Elf64LEObjFile->getELFFile()->getHeader()->e_type;
  if ((EType == ELF::ET_DYN) || (EType == ELF::ET_EXEC)) {
    uint64_t PCOffset = TextSectionAddress + MCInstOffset + MCInstSz + Disp;
    const RelocationRef *DynReloc = MR->getDynRelocAtOffset(PCOffset);

    // assert(DynReloc &&
    //       "Failed to get dynamic relocation for pc-relative offset");
    // If there is a dynamic relocation for the PCOffset
    if (DynReloc) {
      if (DynReloc->getType() == ELF::R_X86_64_GLOB_DAT) {
        Expected<StringRef> Symname = DynReloc->getSymbol()->getName();
        assert(Symname &&
               "Failed to find symbol associated with dynamic relocation.");
        // Find if a global value associated with symbol name is already
        // created
        for (GlobalVariable &GV : MR->getModule()->globals()) {
          if (GV.getName().compare(Symname.get()) == 0) {
            MemrefValue = &GV;
          }
        }
        if (MemrefValue == nullptr) {
          // Get all necessary information about the global symbol.
          llvm::LLVMContext &Ctx(MF.getFunction().getContext());
          DataRefImpl SymbImpl = DynReloc->getSymbol()->getRawDataRefImpl();
          // get symbol
          auto Symb = Elf64LEObjFile->getSymbol(SymbImpl);
          // get symbol size
          uint64_t SymbSize = Symb->st_size;
          GlobalValue::LinkageTypes Lnkg;
          switch (Symb->getBinding()) {
          case ELF::STB_GLOBAL:
            Lnkg = GlobalValue::ExternalLinkage;
            break;
          default:
            assert(false && "Unhandled dynamic symbol");
          }

          // Check that symbol type is data object, representing a variable or
          // array etc.
          assert((Symb->getType() == ELF::STT_OBJECT) &&
                 "Function symbol type expected. Not found");
          Type *GlobalValTy = nullptr;
          switch (SymbSize) {
          case 8:
            GlobalValTy = Type::getInt64Ty(Ctx);
            break;
          case 4:
            GlobalValTy = Type::getInt32Ty(Ctx);
            break;
          case 2:
            GlobalValTy = Type::getInt16Ty(Ctx);
            break;
          case 1:
            GlobalValTy = Type::getInt8Ty(Ctx);
            break;
          default:
            assert(false && "Unexpected symbol size");
          }
          // get symbol value - this is the virtual address of symbol's value
          uint64_t SymVirtualAddr = Symb->st_value;

          // get the initial value of the global data symbol at symVirtualAddr
          // from the section that contains the virtual address
          // symVirtualAddr. In executable and shared object files, st_value
          // holds a virtual address.
          uint64_t SymbVal = 0;
          for (section_iterator SecIter : Elf64LEObjFile->sections()) {
            uint64_t SecStart = SecIter->getAddress();
            uint64_t SecEnd = SecStart + SecIter->getSize();
            if ((SecStart <= SymVirtualAddr) && (SecEnd >= SymVirtualAddr)) {
              // Get the initial symbol value only if this is not a bss
              // section. Else, symVal is already initialized to 0.
              if (SecIter->isBSS()) {
                Lnkg = GlobalValue::CommonLinkage;
              } else {
                StringRef SecData = unwrapOrError(
                    SecIter->getContents(), MR->getObjectFile()->getFileName());
                unsigned Index = SymVirtualAddr - SecStart;
                const unsigned char *Begin = SecData.bytes_begin() + Index;
                char Shift = 0;
                while (SymbSize-- > 0) {
                  // We know this is little-endian
                  SymbVal = ((*Begin++) << Shift) | SymbVal;
                  Shift += 8;
                }
              }
              break;
            }
          }
          Constant *GlobalInit = ConstantInt::get(GlobalValTy, SymbVal);
          auto GlobalVal = new GlobalVariable(*(MR->getModule()), GlobalValTy,
                                              false /* isConstant */, Lnkg,
                                              GlobalInit, Symname->data());
          // Don't use symbSize as it was modified.
          GlobalVal->setAlignment(MaybeAlign(Symb->st_size));
          GlobalVal->setDSOLocal(true);
          MemrefValue = GlobalVal;
        }
      } else {
        assert(false && "Unexpected relocation type referenced in PC-relative "
                        "memory access instruction.");
      }
    } else {
      MemrefValue = getGlobalVariableValueAt(MI, PCOffset);
    }
  } else if (EType == ELF::ET_REL) {
    const RelocationRef *TextReloc =
        MR->getTextRelocAtOffset(MCInstOffset, MCInstSz);

    assert(TextReloc &&
           "Failed to get dynamic relocation for pc-relative offset");

    if (TextReloc->getType() == ELF::R_X86_64_32S) {
      Expected<StringRef> Symname = TextReloc->getSymbol()->getName();
      assert(Symname &&
             "Failed to find symbol associated with text relocation.");
      // Find if a global value associated with symbol name is already
      // created
      for (GlobalVariable &GV : MR->getModule()->globals()) {
        if (GV.getName().compare(Symname.get()) == 0) {
          MemrefValue = &GV;
        }
      }
      if (MemrefValue == nullptr) {
        // Get all necessary information about the text relocation symbol
        // which is most likely global.

        llvm::LLVMContext &Ctx(MF.getFunction().getContext());
        DataRefImpl symbImpl = TextReloc->getSymbol()->getRawDataRefImpl();
        // get symbol
        auto Symb = Elf64LEObjFile->getSymbol(symbImpl);
        // get symbol size
        uint64_t SymSize = Symb->st_size;
        GlobalValue::LinkageTypes Lnkg;
        switch (Symb->getBinding()) {
        case ELF::STB_GLOBAL:
          Lnkg = GlobalValue::ExternalLinkage;
          break;
        default:
          assert(false && "Unhandled dynamic symbol");
        }

        // get symbol value - this is the offset from the beginning of the
        // section st_shndex identifies.
        uint64_t SymVal = Symb->st_value;

        uint64_t SymValSecIndex = Symb->st_shndx;
        uint8_t SymAlignment = 0;
        uint64_t SymInitVal = 0;
        if (((SymValSecIndex >= ELF::SHN_LORESERVE) &&
             (SymValSecIndex <= ELF::SHN_HIRESERVE)) ||
            (SymValSecIndex == ELF::SHN_UNDEF)) {
          if (SymValSecIndex == ELF::SHN_COMMON) {
            // st_value holds symbol alignment constraints
            SymAlignment = SymVal;
            Lnkg = GlobalValue::CommonLinkage;
          }
        } else {
          // get the initial value of the global data symbol at offset symVal
          // in section with index symValSecIndex

          for (section_iterator SecIter : Elf64LEObjFile->sections()) {
            if (SecIter->getIndex() == SymValSecIndex) {
              StringRef SecData = unwrapOrError(
                  SecIter->getContents(), MR->getObjectFile()->getFileName());
              const unsigned char *Begin = SecData.bytes_begin() + SymVal;
              char Shift = 0;
              while (SymSize-- > 0) {
                // We know this is little-endian
                SymInitVal = ((*Begin++) << Shift) | SymInitVal;
                Shift += 8;
              }
              break;
            }
          }
          // REVISIT : Set symbol alignment to be the same as symbol size
          // NOTE : Do not use symSize since it has been modified in the while
          // loop above.
          SymAlignment = Symb->st_size;
        }
        Type *GlobalValTy = nullptr;

        switch (SymAlignment) {
        case 8:
          GlobalValTy = Type::getInt64Ty(Ctx);
          break;
        case 4:
          GlobalValTy = Type::getInt32Ty(Ctx);
          break;
        case 2:
          GlobalValTy = Type::getInt16Ty(Ctx);
          break;
        case 1:
          GlobalValTy = Type::getInt8Ty(Ctx);
          break;
        default:
          assert(false && "Unexpected symbol size");
        }

        Constant *GlobalInit = ConstantInt::get(GlobalValTy, SymInitVal);
        auto GlobalVal = new GlobalVariable(*(MR->getModule()), GlobalValTy,
                                            false /* isConstant */, Lnkg,
                                            GlobalInit, Symname->data());
        // Don't use symSize as it was modified.
        GlobalVal->setAlignment(MaybeAlign(SymAlignment));
        GlobalVal->setDSOLocal(true);
        MemrefValue = GlobalVal;
      }
    } else {
      assert(false && "Unexpected relocation type referenced in PC-relative "
                      "memory access instruction.");
    }
  } else {
    assert(false && "Unhandled binary type. Only object files and shared "
                    "libraries supported");
  }
  return MemrefValue;
}

// Promote the ReachingValue of PhysReg defined in DefiningMBB to specified
// stack slot Alloca.
StoreInst *X86MachineInstructionRaiser::promotePhysregToStackSlot(
    int PhysReg, Value *ReachingValue, int DefiningMBB, AllocaInst *Alloca) {
  StoreInst *StInst = nullptr;
  LLVMContext &Ctxt(MF.getFunction().getContext());

  assert((ReachingValue != nullptr) &&
         "Null incoming value of reaching definition found");
  assert(raisedValues->getInBlockRegOrArgDefVal(PhysReg, DefiningMBB).second ==
             ReachingValue &&
         "Inconsistent reaching defined value found");
  assert(ReachingValue->getType()->isIntOrPtrTy() &&
         "Unsupported: Stack promotion of non-integer / non-pointer value");
  // Prepare to store this value in stack location.
  // Get the size of defined physical register
  int DefinedPhysRegSzInBits =
      raisedValues->getInBlockPhysRegSize(PhysReg, DefiningMBB);
  assert(((DefinedPhysRegSzInBits == 64) || (DefinedPhysRegSzInBits == 32) ||
          (DefinedPhysRegSzInBits == 16) || (DefinedPhysRegSzInBits == 8) ||
          (DefinedPhysRegSzInBits == 1)) &&
         "Unexpected physical register size of reaching definition ");
  // This could simply be set to 64 because the stack slot allocated is
  // a 64-bit value.
  int StackLocSzInBits =
      Alloca->getType()->getPointerElementType()->getPrimitiveSizeInBits();
  // Cast the current value to int64 if needed
  Type *StackLocTy = Type::getIntNTy(Ctxt, StackLocSzInBits);
  BasicBlock *ReachingBB =
      getRaisedBasicBlock(MF.getBlockNumbered(DefiningMBB));
  // get terminating instruction. Add new instructions before
  // terminator instruction if one exists.
  Instruction *TermInst = ReachingBB->getTerminator();
  if (StackLocTy != ReachingValue->getType()) {
    CastInst *CInst = CastInst::Create(
        CastInst::getCastOpcode(ReachingValue, false, StackLocTy, false),
        ReachingValue, StackLocTy);
    if (TermInst == nullptr)
      ReachingBB->getInstList().push_back(CInst);
    else
      CInst->insertBefore(TermInst);
    ReachingValue = CInst;
  }
  StInst = new StoreInst(ReachingValue, Alloca);
  if (TermInst == nullptr)
    ReachingBB->getInstList().push_back(StInst);
  else
    StInst->insertBefore(TermInst);

  return StInst;
}

// Promote any reaching definitions that remained unpromoted.
bool X86MachineInstructionRaiser::handleUnpromotedReachingDefs() {
  for (auto RDToFix : reachingDefsToPromote) {
    unsigned PReg = std::get<0>(RDToFix);
    unsigned int SuperReg = find64BitSuperReg(PReg);
    unsigned int DefiningMBBNo = std::get<1>(RDToFix);
    Value *Val = std::get<2>(RDToFix);
    assert((isa<AllocaInst>(Val)) &&
           "Found value that is not a stack location "
           "during reaching definition fixup");
    AllocaInst *Alloca = dyn_cast<AllocaInst>(Val);
    Value *ReachingDef =
        raisedValues->getInBlockRegOrArgDefVal(PReg, DefiningMBBNo).second;
    assert((ReachingDef != nullptr) &&
           "Null reaching definition found during reaching definition fixup");
    StoreInst *StInst = promotePhysregToStackSlot(SuperReg, ReachingDef,
                                                  DefiningMBBNo, Alloca);
    assert(StInst != nullptr && "Failed to promote register to memory");
  }
  return true;
}

// Adjust sizes of stack allocated objects. Ensure all allocations account
// for the stack size of the function deduced from the machine code.
bool X86MachineInstructionRaiser::adjustStackAllocatedObjects() {
  MachineFrameInfo &MFrameInfo = MF.getFrameInfo();
  const DataLayout &dataLayout = MR->getModule()->getDataLayout();
  // Map of stack offset and stack index
  std::map<int64_t, int> StackOffsetToIndexMap;
  std::map<int64_t, int>::iterator StackOffsetToIndexMapIter;
  LLVMContext &llvmContext(MF.getFunction().getContext());
  for (int StackIndex = MFrameInfo.getObjectIndexBegin();
       StackIndex < MFrameInfo.getObjectIndexEnd(); StackIndex++) {
    int64_t ObjOffset = MFrameInfo.getObjectOffset(StackIndex);
    assert(StackOffsetToIndexMap.find(ObjOffset) ==
               StackOffsetToIndexMap.end() &&
           "Multiple stack objects with same offset found");
    StackOffsetToIndexMap.emplace(
        std::pair<int64_t, int>(ObjOffset, StackIndex));
  }

  StackOffsetToIndexMapIter = StackOffsetToIndexMap.begin();
  while (StackOffsetToIndexMapIter != StackOffsetToIndexMap.end()) {
    auto Entry = *StackOffsetToIndexMapIter;
    int64_t StackOffset = Entry.first;
    int StackIndex = Entry.second;
    AllocaInst *allocaInst =
        const_cast<AllocaInst *>(MFrameInfo.getObjectAllocation(StackIndex));
    // No need to look at the alloca instruction created to demarcate the
    // stack pointer adjustment. It stack allocation does not have a
    // corresponding reference in the binary being raised.
    if (!allocaInst->getName().startswith("StackAdj")) {
      auto NextEntryIter = std::next(StackOffsetToIndexMapIter);
      if (NextEntryIter != StackOffsetToIndexMap.end()) {
        int64_t NextStackOffset = NextEntryIter->first;
        // Get stack slot size in bytes between current stack object
        // and the next stack object
        int SlotSize = abs(StackOffset - NextStackOffset);
        // Slot size should be equal to or greater than sizeof alloca type
        // times number of elements.
        auto allocaBitCount = allocaInst->getAllocationSizeInBits(dataLayout);
        assert(allocaBitCount.hasValue() &&
               "Failed to get size of alloca instruction");
        int allocaByteCount = allocaBitCount.getValue() / 8;
        // assert((allocaByteCount >= SlotSize) &&
        //       "Incorrect size of stack slot allocated");
        if (allocaByteCount < SlotSize) {
          // Change alloca size to match the slot size
          // Value *sz = allocaInst->getArraySize();
          // sz->dump();
          int NewAllocaCount = ((SlotSize % allocaByteCount) == 0)
                                   ? (SlotSize / allocaByteCount)
                                   : (SlotSize / allocaByteCount) + 1;
          Value *Count =
              ConstantInt::get(llvmContext, APInt(32, NewAllocaCount));
          allocaInst->setOperand(0, Count);
        }
      }
    }
    // Go to next entry
    StackOffsetToIndexMapIter++;
  }
  return true;
}

Value *X86MachineInstructionRaiser::getStackAllocatedValue(
    const MachineInstr &MI, X86AddressMode &MemRef, bool IsStackPointerAdjust) {
  unsigned int stackFrameIndex;

  assert((MemRef.BaseType == X86AddressMode::RegBase) &&
         "Register type operand expected for stack allocated value lookup");
  unsigned PReg = find64BitSuperReg(MemRef.Base.Reg);
  assert(((PReg == X86::RSP) || (PReg == X86::RBP)) &&
         "Stack or base pointer expected for stack allocated value lookup");
  Value *CurSPVal = getRegOrArgValue(PReg, MI.getParent()->getNumber());

  // If the memory reference offset is 0 i.e., not different from the current
  // sp reference and there is already a stack allocation, just return that
  // value
  if ((MemRef.Disp == 0) && (CurSPVal != nullptr)) {
    if (Instruction *I = dyn_cast<Instruction>(CurSPVal)) {
      if (hasRODataAccess(I))
        // Refers to rodata; so has no sp allocation;
        return nullptr;
    }
    return CurSPVal;
  }
  // At this point, the stack offset specified in the memory opernad is
  // different from that of the alloca corresponding to sp or there is no
  // stack allocation corresponding to sp.
  int NewDisp;
  MachineFrameInfo &MFrameInfo = MF.getFrameInfo();
  // If there is no allocation corresponding to sp, set the offset of new
  // allocation to be that specified in memory operand.
  if (CurSPVal == nullptr) {
    NewDisp = MemRef.Disp;
  } else {
    // If the sp/bp do not reference a stack allocation, return nullptr
    if (!isa<AllocaInst>(CurSPVal)) {
      // Check if this is an instruction that loads from stack (i.e., alloc)
      LoadInst *LoadAllocInst = dyn_cast<LoadInst>(CurSPVal);
      if (LoadAllocInst) {
        if (hasRODataAccess(LoadAllocInst))
          // Refers to rodata; so has no sp allocation;
          return nullptr;
        // Set current SP value to be the alloc being loaded from.
        CurSPVal = LoadAllocInst->getPointerOperand();
      } else {
        return nullptr;
      }
    }
    assert((MemRef.Disp != 0) && "Unexpected 0 offset value");
    // Find the stack offset of the allocation corresponding to current sp
    bool IndexFound = false;
    unsigned ObjCount = MFrameInfo.getNumObjects();
    unsigned StackIndex = 0;
    for (; ((StackIndex < ObjCount) && !IndexFound); StackIndex++) {
      IndexFound = (CurSPVal == MFrameInfo.getObjectAllocation(StackIndex));
    }
    assert(IndexFound && "Failed to get current stack allocation index");
    // Get stack offset of the stack object at StackIndex-1 and add the
    // specified offset to get the displacement of the referenced stack
    // object.
    NewDisp = MFrameInfo.getObjectOffset(StackIndex - 1) + MemRef.Disp;
  }
  // Look for alloc with offset NewDisp
  bool StackIndexFound = false;
  unsigned NumObjs = MFrameInfo.getNumObjects();
  unsigned StackIndex = 0;
  for (; ((StackIndex < NumObjs) && !StackIndexFound); StackIndex++) {
    StackIndexFound = (NewDisp == MFrameInfo.getObjectOffset(StackIndex));
  }
  if (StackIndexFound) {
    AllocaInst *Alloca = const_cast<AllocaInst *>(
        MFrameInfo.getObjectAllocation(StackIndex - 1));
    assert((Alloca != nullptr) && "Failed to look up stack allocated object");
    assert(isa<Value>(Alloca) &&
           "Alloca instruction expected to be associated with stack object");
    return dyn_cast<AllocaInst>(Alloca);
  }
  // No stack object found with offset NewDisp. Create one.
  Type *Ty = nullptr;
  unsigned int typeAlignment;
  LLVMContext &llvmContext(MF.getFunction().getContext());
  const DataLayout &dataLayout = MR->getModule()->getDataLayout();
  unsigned allocaAddrSpace = dataLayout.getAllocaAddrSpace();
  unsigned stackObjectSize = getInstructionMemOpSize(MI.getOpcode());
  switch (stackObjectSize) {
  default:
    Ty = Type::getInt64Ty(llvmContext);
    stackObjectSize = 8;
    break;
  case 4:
    Ty = Type::getInt32Ty(llvmContext);
    break;
  case 2:
    Ty = Type::getInt16Ty(llvmContext);
    break;
  case 1:
    Ty = Type::getInt8Ty(llvmContext);
    break;
  }

  assert(stackObjectSize != 0 && Ty != nullptr &&
         "Unknown type of operand in memory referencing instruction");
  typeAlignment = dataLayout.getPrefTypeAlignment(Ty);

  // Create alloca instruction to allocate stack slot
  AllocaInst *alloca =
      new AllocaInst(Ty, allocaAddrSpace, 0, MaybeAlign(typeAlignment),
                     IsStackPointerAdjust ? "StackAdj" : "");

  // Create a stack slot associated with the alloca instruction
  stackFrameIndex = MF.getFrameInfo().CreateStackObject(
      stackObjectSize, dataLayout.getPrefTypeAlignment(Ty),
      false /* isSpillSlot */, alloca);

  // Set NewDisp as the offset for stack frame object created.
  MF.getFrameInfo().setObjectOffset(stackFrameIndex, NewDisp);
  // Add the alloca instruction to entry block
  insertAllocaInEntryBlock(alloca);

  return alloca;
}

// Return the Function * referenced by the PLT entry at offset
Function *X86MachineInstructionRaiser::getTargetFunctionAtPLTOffset(
    const MachineInstr &mi, uint64_t pltEntOff) {
  Function *CalledFunc = nullptr;
  const ELF64LEObjectFile *Elf64LEObjFile =
      dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
  assert(Elf64LEObjFile != nullptr &&
         "Only 64-bit ELF binaries supported at present.");
  unsigned char ExecType = Elf64LEObjFile->getELFFile()->getHeader()->e_type;
  assert((ExecType == ELF::ET_DYN) || (ExecType == ELF::ET_EXEC));
  // Find the section that contains the offset. That must be the PLT section
  for (section_iterator SecIter : Elf64LEObjFile->sections()) {
    uint64_t SecStart = SecIter->getAddress();
    uint64_t SecEnd = SecStart + SecIter->getSize();
    if ((SecStart <= pltEntOff) && (SecEnd >= pltEntOff)) {
      StringRef SecName;
      if (auto NameOrErr = SecIter->getName())
        SecName = *NameOrErr;
      else {
        consumeError(NameOrErr.takeError());
        assert(false && "Failed to get section name with PLT offset");
      }
      if (SecName.compare(".plt") != 0)
        continue;
      StringRef SecData = unwrapOrError(SecIter->getContents(),
                                        MR->getObjectFile()->getFileName());
      ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(SecData.data()),
                              SecData.size());
      // Disassemble the first instruction at the offset
      MCInst Inst;
      uint64_t InstSz;
      bool Success = MR->getMCDisassembler()->getInstruction(
          Inst, InstSz, Bytes.slice(pltEntOff - SecStart), pltEntOff, nulls(),
          nulls());
      assert(Success && "Failed to disassemble instruction in PLT");
      unsigned int Opcode = Inst.getOpcode();
      MCInstrDesc MCID = MR->getMCInstrInfo()->get(Opcode);
      if ((Opcode != X86::JMP64m) || (MCID.getNumOperands() != 5)) {
        assert(false && "Unexpected non-jump instruction or number of operands "
                        "of jmp instruction in PLT entry");
      }
      MCOperand Oprnd = Inst.getOperand(0);
      int64_t PCOffset = 0;

      // First operand should be PC
      if (Oprnd.isReg()) {
        if (Oprnd.getReg() != X86::RIP) {
          assert(false && "PC-relative jmp instruction expected in PLT entry");
        }
      } else {
        assert(false && "PC operand expected in jmp instruction of PLT entry");
      }

      Oprnd = Inst.getOperand(1);
      // Second operand should be 1
      if (Oprnd.isImm()) {
        if (Oprnd.getImm() != 1) {
          assert(false && "Unexpected immediate second operand in jmp "
                          "instruction of PLT entry");
        }
      } else {
        assert(false && "Unexpected non-immediate second operand in jmp "
                        "instruction of PLT entry");
      }

      Oprnd = Inst.getOperand(2);
      // Third operand should be X86::No_Register
      if (Oprnd.isReg()) {
        if (Oprnd.getReg() != X86::NoRegister) {
          assert(false && "Unexpected third operand - non-zero register in jmp "
                          "instruction of PLT entry");
        }
      } else {
        assert(false && "Unexpected third operand - non-register in jmp "
                        "instruction of PLT entry");
      }

      Oprnd = Inst.getOperand(3);
      // Fourth operand should be an immediate
      if (!Oprnd.isImm()) {
        assert(false && "Unexpected non-immediate fourth operand in jmp "
                        "instruction of PLT entry");
      }
      // Get the pc offset
      PCOffset = Oprnd.getImm();

      Oprnd = Inst.getOperand(4);
      // Fifth operand should be X86::No_Register
      if (Oprnd.isReg()) {
        if (Oprnd.getReg() != X86::NoRegister) {
          assert(false && "Unexpected fifth operand - non-zero register in jmp "
                          "instruction of PLT entry");
        }
      } else {
        assert(false && "Unexpected fifth operand - non-register in jmp "
                        "instruction of PLT entry");
      }

      // Get dynamic relocation in .got.plt section corresponding to the PLT
      // entry. The relocation offset is calculated by adding the following:
      //    a) offset of jmp instruction + size of the instruction
      //    (representing pc-related addressing) b) jmp target offset in the
      //    instruction
      uint64_t GotPltRelocOffset = pltEntOff + InstSz + PCOffset;
      const RelocationRef *GotPltReloc =
          MR->getDynRelocAtOffset(GotPltRelocOffset);
      assert(GotPltReloc != nullptr &&
             "Failed to get dynamic relocation for jmp target of PLT entry");

      assert((GotPltReloc->getType() == ELF::R_X86_64_JUMP_SLOT) &&
             "Unexpected relocation type for PLT jmp instruction");
      symbol_iterator CalledFuncSym = GotPltReloc->getSymbol();
      assert(CalledFuncSym != Elf64LEObjFile->symbol_end() &&
             "Failed to find relocation symbol for PLT entry");
      Expected<StringRef> CalledFuncSymName = CalledFuncSym->getName();
      assert(CalledFuncSymName &&
             "Failed to find symbol associated with dynamic "
             "relocation of PLT jmp target.");
      Expected<uint64_t> CalledFuncSymAddr = CalledFuncSym->getAddress();
      assert(CalledFuncSymAddr &&
             "Failed to get called function address of PLT entry");
      CalledFunc = MR->getRaisedFunctionAt(CalledFuncSymAddr.get());

      if (CalledFunc == nullptr) {
        // This is an undefined function symbol. Look through the list of
        // known glibc interfaces and construct a Function accordingly.
        CalledFunc = ExternalFunctions::Create(*CalledFuncSymName,
                                               *const_cast<ModuleRaiser *>(MR));
      }
      // Found the section we are looking for
      break;
    }
  }
  return CalledFunc;
}

// Return the element pointer to global rodata array corresponding at Offset.
// This returns a Value of type GetElementPtrConstantExpr. However, this type
// can not be used explicitly since it is private to Constants.cpp (See comment
// in llvm/lib/IR/ConstantsContext.h)
Value *X86MachineInstructionRaiser::getOrCreateGlobalRODataValueAtOffset(
    int64_t Offset, Type *OffsetTy1, BasicBlock *InsertBB) {
  // A negative offset implies that this is not an offset into ro-data
  // section. Just return nullptr.
  if (Offset < 0) {
    return nullptr;
  }
  Value *RODataValue = nullptr;
  const ELF64LEObjectFile *Elf64LEObjFile =
      dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
  assert(Elf64LEObjFile != nullptr &&
         "Only 64-bit ELF binaries supported at present.");
  LLVMContext &llvmContext(MF.getFunction().getContext());
  // Check if this is an address in .rodata
  for (section_iterator SecIter : Elf64LEObjFile->sections()) {
    uint64_t SecStart = SecIter->getAddress();
    uint64_t SecEnd = SecStart + SecIter->getSize();
    // We know that Offset is a positive value. So, casting it is OK.
    if ((SecStart <= (uint64_t)Offset) && (SecEnd >= (uint64_t)Offset)) {
      if (SecIter->isData()) {
        // Get the associated global value if one exists
        uint64_t SecIndex = SecIter->getIndex();
        std::string RODataSecValueName;
        if (auto NameOrErr = SecIter->getName())
          // Drop the leading '.' from section name
          RODataSecValueName.append((*NameOrErr).substr(1).data());
        else {
          consumeError(NameOrErr.takeError());
          RODataSecValueName.append("AnonDataSec");
        }

        RODataSecValueName.append("_").append(std::to_string(SecIndex));
        Constant *RODataSecValue = MR->getModule()->getGlobalVariable(
            RODataSecValueName, true /* AllowInternal */);
        // If ROData Value representing the contents of this section was not
        // materialized yet, create one.
        if (RODataSecValue == nullptr) {
          // Create the global variable corresponding to the content of
          // .rodata
          StringRef SecData = unwrapOrError(SecIter->getContents(),
                                            MR->getObjectFile()->getFileName());
          unsigned DataSize = SecIter->getSize();
          auto DataStr = makeArrayRef(SecData.bytes_begin(), DataSize);
          Constant *StrConstant = ConstantDataArray::get(llvmContext, DataStr);
          auto GlobalStrConstVal = new GlobalVariable(
              *(MR->getModule()), StrConstant->getType(), true /* isConstant */,
              GlobalValue::PrivateLinkage, StrConstant, RODataSecValueName);
          GlobalStrConstVal->setAlignment(MaybeAlign(SecIter->getAlignment()));
          // Address is not significant
          GlobalStrConstVal->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
          // Add metadata that indicates the section start
          getRaisedValues()->setGVMetadataRODataInfo(GlobalStrConstVal,
                                                     SecStart);
          RODataSecValue = GlobalStrConstVal;
        }
        unsigned DataOffset = Offset - SecStart;
        // Construct index array for a GEP instruction that accesses
        // byte array
        Value *Zero32Value = ConstantInt::get(Type::getInt32Ty(llvmContext), 0);
        Value *DataOffsetIndex =
            ConstantInt::get(Type::getInt32Ty(llvmContext), DataOffset);
        Constant *GetElem = ConstantExpr::getInBoundsGetElementPtr(
            RODataSecValue->getType()->getPointerElementType(), RODataSecValue,
            {Zero32Value, DataOffsetIndex});
        RODataValue = GetElem;
      }
      break;
    }
  }
  return RODataValue;
}

// Return a value corresponding to global symbol at Offset referenced in
// MachineInst MI.
Value *
X86MachineInstructionRaiser::getGlobalVariableValueAt(const MachineInstr &MI,
                                                      uint64_t Offset) {
  Value *GlobalVariableValue = nullptr;
  const ELF64LEObjectFile *Elf64LEObjFile =
      dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
  assert(Elf64LEObjFile != nullptr &&
         "Only 64-bit ELF binaries supported at present.");
  assert((Offset > 0) &&
         "Unhandled non-positive displacement global variable value");
  // Find symbol at Offset
  SymbolRef GlobalDataSym;
  bool GlobalDataSymFound = false;
  unsigned GlobalDataOffset = 0;
  llvm::LLVMContext &Ctx(MF.getFunction().getContext());

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  for (auto Symbol : Elf64LEObjFile->symbols()) {
    if (Symbol.getELFType() == ELF::STT_OBJECT) {
      auto SymAddr = Symbol.getAddress();
      auto SymSize = Symbol.getSize();
      assert(SymAddr && "Failed to lookup symbol for global address");
      uint64_t SymAddrVal = SymAddr.get();
      // We have established that Offset is not negative above. So, OK to
      // cast.
      // Check if the memory address Offset is in the range [SymAddrVal,
      // SymAddrVal+SymSize)
      if ((SymAddrVal <= (unsigned)Offset) &&
          ((SymAddrVal + SymSize) > (unsigned)Offset)) {
        GlobalDataSym = Symbol;
        GlobalDataOffset = Offset - SymAddrVal;
        GlobalDataSymFound = true;
        break;
      }
    }
  }

  if (!GlobalDataSymFound) {
    // If Offset does not correspond to a global symbol, get the corresponding
    // rodata value.
    GlobalVariableValue = getOrCreateGlobalRODataValueAtOffset(
        Offset, Type::getInt64Ty(MF.getFunction().getContext()), RaisedBB);
  } else {
    // If Offset corresponds to a global symbol, materialize a global
    // variable.
    unsigned MemAccessSizeInBytes = getInstructionMemOpSize(MI.getOpcode());

    // If MI is not a memory accessing instruction, determine the access size by
    // the size of destination register.
    if (MemAccessSizeInBytes == 0) {
      MachineOperand MO = MI.getOperand(0);
      assert(MI.getNumExplicitDefs() == 1 && MO.isReg() &&
             "Expect one explicit register def operand");
      MemAccessSizeInBytes =
          getPhysRegSizeInBits(MO.getReg()) / sizeof(uint64_t);
    }

    assert((MemAccessSizeInBytes != 0) && "Unknown memory access size");
    Expected<StringRef> GlobalDataSymName = GlobalDataSym.getName();
    assert(GlobalDataSymName && "Failed to find global symbol name.");
    // Find if a global value associated with symbol name is already
    // created
    StringRef GlobalDataSymNameIndexStrRef(GlobalDataSymName.get());
    for (GlobalVariable &GV : MR->getModule()->globals()) {
      if (GV.getName().compare(GlobalDataSymNameIndexStrRef) == 0) {
        GlobalVariableValue = &GV;
      }
    }
    // By default, the symbol alignment is the symbol section alignment.
    // Will be adjusted as needed based on the size of the symbol later.
    auto GlobalDataSymSection = GlobalDataSym.getSection();
    assert(GlobalDataSymSection && "No section for global symbol found");
    uint64_t GlobDataSymAlignment = GlobalDataSymSection.get()->getAlignment();
    // Make sure the alignment is a power of 2
    assert(((GlobDataSymAlignment & (GlobDataSymAlignment - 1)) == 0) &&
           "Section alignment not a power of 2");

    if (GlobalVariableValue == nullptr) {
      Type *GlobalValTy = nullptr;
      // Get all necessary information about the global symbol.
      DataRefImpl SymbImpl = GlobalDataSym.getRawDataRefImpl();
      // get symbol
      auto Symb = Elf64LEObjFile->getSymbol(SymbImpl);
      // get symbol size
      uint64_t SymbSize = Symb->st_size;
      // If symbol size is less than symbol section size, set alignment to
      // symbol size.
      if (SymbSize < GlobDataSymAlignment) {
        GlobDataSymAlignment = SymbSize;
      }
      GlobalValue::LinkageTypes Lnkg;
      switch (Symb->getBinding()) {
      case ELF::STB_GLOBAL:
        Lnkg = GlobalValue::ExternalLinkage;
        break;
      case ELF::STB_LOCAL:
        Lnkg = GlobalValue::InternalLinkage;
        break;
      default:
        assert(false && "Unhandled global symbol binding type");
      }

      // Check that symbol type is data object, representing a variable or
      // array etc.
      assert((Symb->getType() == ELF::STT_OBJECT) &&
             "Object symbol type expected. Not found");

      // Memory access is in bytes. So, need to multiply the alignment by 8
      // for the number of bits.
      GlobalValTy = Type::getIntNTy(Ctx, MemAccessSizeInBytes * 8);

      // get symbol value - this is the virtual address of symbol's value
      uint64_t SymVirtualAddr = Symb->st_value;

      // get the initial value of the global data symbol at SymVirtualAddr
      // from the section that contains the virtual address SymVirtualAddr.
      // In executable and shared object files, st_value holds a virtual
      // address.
      SmallVector<Constant *, 32> ConstantVec;
      bool isBSSSymbol = false;
      for (section_iterator SecIter : Elf64LEObjFile->sections()) {
        uint64_t SecStart = SecIter->getAddress();
        uint64_t SecEnd = SecStart + SecIter->getSize();
        if ((SecStart <= SymVirtualAddr) && (SecEnd > SymVirtualAddr)) {
          // Get the initial symbol value only if this is not a bss section.
          // Else, symVal is already initialized to 0.
          if (SecIter->isBSS()) {
            Lnkg = GlobalValue::CommonLinkage;
            isBSSSymbol = true;
          } else {
            StringRef SecData = unwrapOrError(
                SecIter->getContents(), MR->getObjectFile()->getFileName());
            unsigned Index = SymVirtualAddr - SecStart;
            const char *beg =
                reinterpret_cast<const char *>(SecData.bytes_begin() + Index);

            // Symbol size should at least be the same as memory access size of
            // the instruction.
            assert(MemAccessSizeInBytes <= SymbSize &&
                   "Inconsistent values of memory access size and symbol size");
            // Read MemAccesssSize number of bytes and check if they represent
            // addresses in .rodata.
            StringRef SymbolBytes(beg, SymbSize);
            unsigned BytesRead = 0;
            // Symbol array values greater that 8 bytes are not yet supported.
            uint64_t SymArrayElem = 0;
            for (unsigned char B : SymbolBytes) {
              unsigned ByteNum = ++BytesRead % MemAccessSizeInBytes;
              if (ByteNum == 0) {
                // Finish reading one symbol data item of size.
                SymArrayElem |= B << (MemAccessSizeInBytes - 1) * 8;
                // if this is an address in .rodata section
                Value *RODataValue = getOrCreateGlobalRODataValueAtOffset(
                    SymArrayElem, Type::getIntNTy(Ctx, MemAccessSizeInBytes),
                    RaisedBB);
                // If the SymArrElem does not correspond to an .rodata address
                // consider it to be data.
                if (RODataValue == nullptr) {
                  Constant *ConstVal = ConstantInt::get(
                      Ctx, APInt(MemAccessSizeInBytes * 8, SymArrayElem));
                  ConstantVec.push_back(ConstVal);
                } else {
                  // SymArrElem corresponds to an .rodata address,
                  if (isa<ConstantExpr>(RODataValue)) {
                    ConstantVec.push_back(dyn_cast<Constant>(RODataValue));
                  } else {
                    assert(false && "Unhandled global value");
                  }
                }
                // Clear symbol element value
                SymArrayElem = 0;
              } else
                SymArrayElem |= B << (ByteNum - 1) * 8;
            }
            // Ensure that all SymSize bytes were read.
            assert(BytesRead == SymbSize &&
                   "Incorrect number of symbol bytes read");
          }
          break;
        }
      }

      // If symbol size is greater than memory access size of the instruction,
      // the symbol must be referencing an array whose elements were collected
      Constant *GlobalInit = nullptr;
      if (SymbSize > MemAccessSizeInBytes) {
        if (ConstantVec.size()) {
          Constant *ConstArray = ConstantArray::get(
              ArrayType::get(ConstantVec[0]->getType(), ConstantVec.size()),
              ConstantVec);
          GlobalInit = ConstArray;
          GlobalValTy = ConstArray->getType();
          if (ConstantVec[0]->getType()->isIntegerTy()) {
            GlobDataSymAlignment = 4;
          }
        } else {
          // This is an aggregate array whose size is symbSize bytes,
          // initialized by BSS.
          assert(isBSSSymbol && "Unexpected non-BSS symbol encountered");
          Type *ByteType = Type::getInt8Ty(Ctx);
          Type *GlobalArrValTy = ArrayType::get(ByteType, SymbSize);
          GlobalInit = ConstantAggregateZero::get(GlobalArrValTy);

          // Change the global value type to byte type to indicate that the
          // data is interpreted as bytes.
          GlobalValTy = GlobalArrValTy;
        }
      } else {
        // Default initial value of global variable
        uint64_t SV = 0;
        assert(SymbSize == MemAccessSizeInBytes && "Inconsistent symbol sizes");

        if (ConstantVec.size() > 0) {
          // Get type of data value
          Type *CVType = ConstantVec[0]->getType();
          if (CVType->isIntegerTy()) {
            assert(ConstantVec.size() == 1 &&
                   "Inconsistent symbol values of global symbol found");
            // Global value is an integer. So, cast the global value that was
            // read accordingly.
            ConstantInt *CIV = dyn_cast<ConstantInt>(ConstantVec[0]);
            assert(CIV != nullptr && "Unexpected global value type");
            // Set the type of global value according to the based on the type
            // of the cast value.
            SV = CIV->getValue().getSExtValue();
            GlobalInit = ConstantInt::get(GlobalValTy, SV);
          } else if (CVType->isPointerTy()) {
            // ConstantVec[0] is the initial global value and global value
            // type is its type.
            GlobalInit = ConstantVec[0];
            GlobalValTy = CVType;
          } else {
            assert(false && "Unexpected global value type");
          }
        } else
          GlobalInit = ConstantInt::get(GlobalValTy, SV);
      }

      // Now, create the global variable for the symbol at given Offset.
      auto GlobalVal = new GlobalVariable(
          *(MR->getModule()), GlobalValTy, false /* isConstant */, Lnkg,
          GlobalInit, GlobalDataSymNameIndexStrRef);
      GlobalVal->setAlignment(MaybeAlign(GlobDataSymAlignment));
      GlobalVal->setDSOLocal(true);
      GlobalVariableValue = GlobalVal;
    }
    assert(GlobalVariableValue->getType()->isPointerTy() &&
           "Unexpected non-pointer type value in global data offset access");

    // If the global variable is of array type, ensure its type is correct.
    if (GlobalVariableValue->getType()->getPointerElementType()->isArrayTy()) {
      // First index - is 0
      Value *FirstIndex =
          ConstantInt::get(MF.getFunction().getContext(), APInt(32, 0));
      // Find the size of array element
      size_t ArrayElemByteSz = GlobalVariableValue->getType()
                                   ->getPointerElementType()
                                   ->getArrayElementType()
                                   ->getScalarSizeInBits() /
                               8;

      unsigned ScaledOffset = GlobalDataOffset / MemAccessSizeInBytes;

      // Offset index
      Value *OffsetIndex = ConstantInt::get(MF.getFunction().getContext(),
                                            APInt(32, ScaledOffset));
      // If the array element size (in bytes) is not equal to that of the
      // access size of the instructions, cast the array accordingly.
      if (MemAccessSizeInBytes != ArrayElemByteSz) {
        // Note the scaled offset is already calculated appropriately.
        // Get the size of global array
        uint64_t GlobalArraySize = GlobalVariableValue->getType()
                                       ->getPointerElementType()
                                       ->getArrayNumElements();
        // Construct integer type of size memAccessSize bytes. Note that It
        // has been asserted that array element is of integral type.
        PointerType *CastToArrTy = PointerType::get(
            ArrayType::get(Type::getIntNTy(Ctx, MemAccessSizeInBytes * 8),
                           GlobalArraySize / MemAccessSizeInBytes),
            0);

        CastInst *CInst =
            CastInst::Create(CastInst::getCastOpcode(GlobalVariableValue, false,
                                                     CastToArrTy, false),
                             GlobalVariableValue, CastToArrTy);
        RaisedBB->getInstList().push_back(CInst);
        GlobalVariableValue = CInst;
      }
      // Get the element
      Instruction *GetElem = GetElementPtrInst::CreateInBounds(
          GlobalVariableValue->getType()->getPointerElementType(),
          GlobalVariableValue, {FirstIndex, OffsetIndex}, "", RaisedBB);
      GlobalVariableValue = GetElem;
    }
  }

  return GlobalVariableValue;
}

// Construct and return a Value* corresponding to PC-relative memory address
// access. Insert any intermediate values created in the process into
// curBlock.
// Construct and return a Value* corresponding to non-stack memory address
// expression in MachineInstr mi. Insert any intermediate values created in
// the process into curBlock. NOTE: This returns a value that may need to be
// loaded from if the expression does not involve global variable or
// dereferencing the global variable if expression involves global variable.
Value *
X86MachineInstructionRaiser::getMemoryAddressExprValue(const MachineInstr &MI) {
  Value *MemrefValue = nullptr;
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  // Should have found the index of the memory reference operand
  assert(MemoryRefOpIndex != -1 && "Unable to find memory reference "
                                   "operand of a load/store instruction");
  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);

  // LLVM represents memory operands using 5 operands
  //    viz., <opcode> BaseReg, ScaleAmt, IndexReg, Disp, Segment, ...
  // The disassembly in AT&T syntax is shown as
  //      Segment:Disp(BaseReg, IndexReg, ScaleAmt).
  // or as
  //      Segment:[BaseReg + Disp + IndexReg * ScaleAmt]
  // in Intel syntax.
  // effective address is calculated to be Segment:[BaseReg + IndexReg *
  // ScaleAmt + Disp] Segment is typically X86::NoRegister.

  assert(MI.getOperand(MemoryRefOpIndex + X86::AddrSegmentReg).getReg() ==
             X86::NoRegister &&
         "Expect no segment register");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  llvm::LLVMContext &Ctx(MF.getFunction().getContext());
  X86RaisedValueTracker *RVT = getRaisedValues();
  // Construct non-stack memory referencing value
  unsigned BaseReg = MemRef.Base.Reg;
  unsigned IndexReg = MemRef.IndexReg;
  unsigned ScaleAmt = MemRef.Scale;
  int Disp = MemRef.Disp;
  const MachineOperand &SegRegOperand =
      MI.getOperand(MemoryRefOpIndex + X86::AddrSegmentReg);
  // For now, we assume default segment DS (and hence no specification of
  // Segment register.
  assert(SegRegOperand.isReg() && (SegRegOperand.getReg() == X86::NoRegister) &&
         "Unhandled memory reference instruction with non-zero segment "
         "register");

  // IndexReg * ScaleAmt
  // Generate mul scaleAmt, IndexRegVal, if IndexReg is not 0.
  if (IndexReg != X86::NoRegister) {
    Value *IndexRegVal = matchSSAValueToSrcRegSize(MI, IndexReg);
    switch (ScaleAmt) {
    case 0:
      break;
    case 1:
      MemrefValue = IndexRegVal;
      break;
    default: {
      Type *MulValTy = IndexRegVal->getType();
      Value *ScaleAmtValue = ConstantInt::get(MulValTy, ScaleAmt);
      Instruction *MulInst =
          BinaryOperator::CreateMul(ScaleAmtValue, IndexRegVal, "memref-idxreg");
      RaisedBB->getInstList().push_back(MulInst);
      MemrefValue = MulInst;
    } break;
    }
  }

  // BaseReg + IndexReg*ScaleAmt
  // Generate add BaseRegVal, memrefVal (if IndexReg*ScaleAmt was computed)

  if (BaseReg != X86::NoRegister) {
    Value *BaseRegVal = getRegOrArgValue(BaseReg, MI.getParent()->getNumber());
    if (MemrefValue != nullptr) {
      assert((BaseRegVal != nullptr) &&
             "Unexpected null value of base reg while constructing memory "
             "address expression");
      // Ensure the type of BaseRegVal matched that of MemrefValue.
      BaseRegVal = getRaisedValues()->castValue(
          BaseRegVal, MemrefValue->getType(), RaisedBB);
      Instruction *AddInst = BinaryOperator::CreateAdd(BaseRegVal, MemrefValue, "memref-basereg");
      // Propagate rodata related metadata
      RVT->setInstMetadataRODataIndex(BaseRegVal, AddInst);
      RaisedBB->getInstList().push_back(AddInst);
      MemrefValue = AddInst;
    } else {
      MemrefValue = BaseRegVal;
    }
  }

  // BaseReg + Index*ScaleAmt + Disp
  //
  if (Disp != 0) {
    if (MemrefValue != nullptr) {
      Type *DispTy = MemrefValue->getType();
      Value *DispValue = ConstantInt::get(DispTy, Disp);

      // Get a global symbol that represents the displacement, Disp.
      Value *GV = getGlobalVariableValueAt(MI, Disp);
      // If Disp represents a global symbol, generate correct instructions for
      // byte sized access, since displacement is always in terms of bytes. If
      // Disp does not represent a global symbol, consider Disp as a plain
      // integer value.
      if (GV != nullptr) {
        // If it is a global array construct GEP
        if (isa<GetElementPtrInst>(GV)) {
          bool Inbounds = false;
          if (auto *GlobGEP = dyn_cast<GetElementPtrInst>(GV)) {
            Inbounds = GlobGEP->isInBounds();
            if (Inbounds) {
              Type *GlobGEPSrcTy = GlobGEP->getSourceElementType();
              if (GlobGEPSrcTy->isArrayTy()) {
                // If it is not a byte-array
                Type *ByteTy = Type::getInt8Ty(Ctx);
                if (GlobGEPSrcTy->getArrayElementType() != ByteTy) {
                  // Create global byte array type based on the size of
                  // GlobalGEPSrc.
                  unsigned int GlobGEPSrcTySzInBytes =
                      GlobGEPSrcTy->getArrayElementType()
                          ->getScalarSizeInBits() /
                      8;
                  uint64_t SymbSize = GlobGEPSrcTy->getArrayNumElements() *
                                      GlobGEPSrcTySzInBytes;
                  Type *ByteArrValTy = ArrayType::get(ByteTy, SymbSize);

                  // Cast array operand of GlobalGEP to ByteArrTy
                  PointerType *ByteArrValPtrTy = ByteArrValTy->getPointerTo();
                  CastInst *CastToArrInst = CastInst::Create(
                      CastInst::getCastOpcode(GlobGEP->getPointerOperand(),
                                              false, ByteArrValPtrTy, false),
                      GlobGEP->getPointerOperand(), ByteArrValPtrTy);
                  // Propagate rodata related metadata
                  RVT->setInstMetadataRODataIndex(GV, CastToArrInst);
                  RaisedBB->getInstList().push_back(CastToArrInst);

                  // Construct index array for a GEP instruction that accesses
                  // byte array
                  std::vector<Value *> ByteAccessGEPIdxArr;
                  for (auto IdxIter = GlobGEP->idx_begin();
                       IdxIter != GlobGEP->idx_end(); IdxIter++) {
                    Value *IdxVal = IdxIter->get();
                    // Special case for index value of 0
                    if (isa<ConstantInt>(IdxVal)) {
                      ConstantInt *ConstIdxVal = dyn_cast<ConstantInt>(IdxVal);
                      if (ConstIdxVal->getSExtValue() == 0) {
                        ByteAccessGEPIdxArr.push_back(IdxVal);
                        continue;
                      }
                    }
                    // Index value not zero. So, scale it up by multiplying
                    // with GlobGEPSrcTySzInBytes, since the we are changing
                    // the access to byte array access.
                    Constant *ScaleVal = ConstantInt::get(IdxVal->getType(),
                                                          GlobGEPSrcTySzInBytes,
                                                          false /* isSigned */);
                    Instruction *IdxMulInst =
                        BinaryOperator::CreateNSWMul(ScaleVal, IdxVal);
                    // Insert the new instruction
                    RaisedBB->getInstList().push_back(IdxMulInst);
                    // Add the value to array used to construct new GEP
                    ByteAccessGEPIdxArr.push_back(IdxVal);
                  }
                  // Create new GEP.
                  Instruction *ByteAccessGEP =
                      GetElementPtrInst::CreateInBounds(
                          ByteArrValTy, CastToArrInst,
                          ArrayRef<Value *>(ByteAccessGEPIdxArr), "", RaisedBB);
                  DispValue = ByteAccessGEP;
                } else {
                  // Global GEP is already a byte array.
                  DispValue = GlobGEP;
                }
                assert(isa<Instruction>(DispValue) &&
                       "Expect Instruction - memory address expression "
                       "abstraction");
                // Cast the byte access GEP to MemrefValue type as needed
                // Using dyn_cast<Instruction> to cast the result of castValue
                // is correct as we know that DispValue is an instruction;
                // castValue returns ByteAccessGEP (an Instruction) if no cast
                // is done or a value of type CastInst, if cast is done.
                DispValue = dyn_cast<Instruction>(getRaisedValues()->castValue(
                    DispValue, MemrefValue->getType(), RaisedBB));
              } else {
                assert(false && "Unhandled situation where global symbol GEP "
                                "is not an array");
              }
            } else {
              assert(false && "Unhandled situation where global symbol GEP is "
                              "not inbounds");
            }
          }
        } else if (GV->getType()->isPointerTy()) {
          // Global value is expected to be an pointer type to an integer type.
          // Cast GV in accordance with the type of MemrefValue to facilitate
          // the addition performed later to construct the address expression.
          if (GV->getType()->getPointerElementType()->isIntegerTy()) {

            DispValue = getRaisedValues()->castValue(GV, MemrefValue->getType(),
                                                     RaisedBB);
          } else {
            assert(false && "Unhandled non-integer pointer global symbol type "
                            "while computing memory address expression");
          }
        } else {
          assert(false && "Unhandled global symbol type while computing "
                          "memory address expression");
        }
      }
      // Generate add memrefVal, Disp.
      Instruction *AddInst = BinaryOperator::CreateAdd(MemrefValue, DispValue, "memref-disp");
      getRaisedValues()->setInstMetadataRODataIndex(MemrefValue, AddInst);
      getRaisedValues()->setInstMetadataRODataIndex(DispValue, AddInst);
      RaisedBB->getInstList().push_back(AddInst);
      MemrefValue = AddInst;
    } else {
      // Check that this is an instruction of the kind
      // mov %rax, 0x605798 which in reality is
      // mov %rax, 0x605798(X86::NoRegister, X86::NoRegister, 1)
      if (BaseReg == X86::NoRegister) {
        assert(((IndexReg == X86::NoRegister) && (ScaleAmt == 1)) &&
               "Unhandled index register in memory addr expression "
               "calculation");
        MemrefValue = getGlobalVariableValueAt(MI, Disp);
        // Construct a PC-relative value if base register is RIP
      } else if (BaseReg == X86::RIP) {
        MemrefValue = createPCRelativeAccesssValue(MI);
      } else {
        assert(false && "Unhandled addressing mode in memory addr "
                        "expression calculation");
      }
    }
  }
  assert((MemrefValue != nullptr) && "Failed to get memory reference value");
  return MemrefValue;
}

// Find SSA value associated with physical register PReg.
// If the PReg is an argument register and hence does not have a previous
// definition, function prototype is consulted to return the corresponding
// value. In that case, return argument value associated with physical
// register PReg according to C calling convention. This function simply
// returns the value of PReg. It does not make any attempt to cast it to match
// the PReg type.

// NOTE : This is the preferred API to get the SSA value associated
//        with PReg.
Value *X86MachineInstructionRaiser::getRegOrArgValue(unsigned PReg, int MBBNo) {
  Value *PRegValue = raisedValues->getReachingDef(PReg, MBBNo);

  // Just return the value associated with PReg, if one exists.
  if (PRegValue == nullptr) {
    int pos = getArgumentNumber(PReg);

    // If PReg is an argument register, get its value from function
    // argument list.
    if (pos > 0) {
      // Get the value only if the function has an argument at
      // pos.
      if (pos <= (int)raisedFunction->arg_size()) {
        Function::arg_iterator argIter = raisedFunction->arg_begin() + pos - 1;
        PRegValue = argIter;
      }
    }
  }
  return PRegValue;
}
// Find SSA value associated with operand at OpIndex, if it is a physical
// register. This function calls getRegOrArgValue() and generates a cast
// instruction to match the type of operand register.

Value *X86MachineInstructionRaiser::getRegOperandValue(const MachineInstr &MI,
                                                       unsigned OpIndex) {
  const MachineOperand &MO = MI.getOperand(OpIndex);
  Value *PRegValue = nullptr; // Unknown, to start with.
  if (MO.isReg()) {
    PRegValue = getRegOrArgValue(MO.getReg(), MI.getParent()->getNumber());
  }

  if (PRegValue != nullptr) {
    // Cast the value in accordance with the register size of the operand,
    // as needed.
    Type *PRegTy = getPhysRegOperandType(MI, OpIndex);
    // Get the BasicBlock corresponding to MachineBasicBlock of MI.
    BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
    PRegValue = getRaisedValues()->castValue(PRegValue, PRegTy, RaisedBB);
  }
  return PRegValue;
}

// Find the index of the first memory reference operand.
int X86MachineInstructionRaiser::getMemoryRefOpIndex(const MachineInstr &mi) {
  const MCInstrDesc &Desc = mi.getDesc();
  int memOperandNo = X86II::getMemoryOperandNo(Desc.TSFlags);
  if (memOperandNo >= 0)
    memOperandNo += X86II::getOperandBias(Desc);
  return memOperandNo;
}

bool X86MachineInstructionRaiser::insertAllocaInEntryBlock(
    Instruction *alloca) {
  // Avoid using BasicBlock InstrList iterators so that the tool can use LLVM
  // built with LLVM_ABI_BREAKING_CHECKS ON or OFF.
  BasicBlock &EntryBlock = getRaisedFunction()->getEntryBlock();

  BasicBlock::InstListType &InstList = EntryBlock.getInstList();
  if (InstList.size() == 0) {
    InstList.push_back(alloca);
  } else {
    // Find the last alloca instruction in the block
    Instruction *Inst = &EntryBlock.back();
    while (Inst != nullptr) {
      if (Inst->getOpcode() == Instruction::Alloca) {
        InstList.insertAfter(Inst->getIterator(), alloca);
        break;
      }
      Inst = Inst->getPrevNode();
    }

    // If there is no alloca instruction yet, push to front
    if (Inst == nullptr)
      InstList.push_front(alloca);
  }
  return true;
}

// Check the sizes of the operand register PReg and that of the corresponding
// SSA value. Return a value that is either truncated or sign-extended version
// of the SSA Value if their sizes do not match. Return the SSA value of the
// operand register PReg, if they match. This is handles the situation following
// pattern of instructions
//   rax <- ...
//   edx <- opcode eax, ...
Value *
X86MachineInstructionRaiser::matchSSAValueToSrcRegSize(const MachineInstr &MI,
                                                       unsigned PReg) {
  assert(Register::isPhysicalRegister(PReg) &&
         "Expect physical register to get SSA value");
  unsigned SrcOpSize = getPhysRegSizeInBits(PReg);
  Value *SrcOpValue = getRegOrArgValue(PReg, MI.getParent()->getNumber());
  const DataLayout &dataLayout = MR->getModule()->getDataLayout();

  if (SrcOpValue) {
    // Generate the appropriate cast instruction if the sizes of the current
    // source value and that of the source register do not match.
    uint64_t SrcValueSize = dataLayout.getTypeSizeInBits(SrcOpValue->getType());
    if (SrcOpSize != SrcValueSize) {
      // Get the BasicBlock corresponding to MachineBasicBlock of MI.
      BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
      Type *CastTy = Type::getIntNTy(MF.getFunction().getContext(), SrcOpSize);
      CastInst *CInst = CastInst::Create(
          CastInst::getCastOpcode(SrcOpValue, false, CastTy, false), SrcOpValue,
          CastTy);
      RaisedBB->getInstList().push_back(CInst);
      SrcOpValue = CInst;
    }
  } else {
    dbgs() << "***** Uninitialized register usage found\n";
    dbgs() << "*****" << MR->getModule()->getSourceFileName() << ": "
           << MF.getName().data() << "\n\t";
    MI.print(dbgs());
  }
  return SrcOpValue;
}

// Record information to raise a terminator instruction in a later pass.
bool X86MachineInstructionRaiser::recordMachineInstrInfo(
    const MachineInstr &MI) {
  // Return instruction is a Terminator. There is nothing to record.
  // Its raising is handled as a normal instruction. This function should
  // not be called when mi is a call instruction.
  assert(MI.isTerminator() && "Not a terminator instruction - can not record "
                              "control transfer information");
  assert(!MI.isReturn() &&
         "Unexpected attempt to record info for a return instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Check if this is jmp instruction that is in reality a tail call.
  bool TailCall = false;
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
        uint64_t MCInstOffset = MCIR->getMCInstIndex(MI);

        assert(MCIR != nullptr && "MCInstRaiser not initialized");
        int64_t BranchTargetOffset =
            MCInstOffset + MCIR->getMCInstSize(MCInstOffset) + BranchOffset;
        const int64_t TgtMBBNo =
            MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset);

        // If the target is not a known target basic block, attempt to raise
        // this instruction as a call.
        if (TgtMBBNo == -1) {
          TailCall = raiseCallMachineInstr(MI);
        }
      }
    }
  }
  // If the instruction is not a tail-call record instruction info for
  // processing at a later stage.
  if (!TailCall) {
    // Set common info of the record
    ControlTransferInfo *CurCTInfo = new ControlTransferInfo;
    CurCTInfo->CandidateMachineInstr = &MI;
    CurCTInfo->CandidateBlock = RaisedBB;

    const MCInstrDesc &MCID = MI.getDesc();
    // Save all values of implicitly used operands
    unsigned ImplUsesCount = MCID.getNumImplicitUses();
    if (ImplUsesCount > 0) {
      const MCPhysReg *ImplUses = MCID.getImplicitUses();
      for (unsigned i = 0; i < ImplUsesCount; i++) {
        // Get the reaching definition of the implicit use register.
        if (ImplUses[i] == X86::EFLAGS) {
          for (auto FlgBit : EFlagBits) {
            Value *Val = getRegOrArgValue(FlgBit, MI.getParent()->getNumber());
            assert((Val != nullptr) &&
                   "Unexpected null value of implicit eflags bits");
            CurCTInfo->RegValues.push_back(Val);
          }
        } else {
          Value *Val =
              getRegOrArgValue(ImplUses[i], MI.getParent()->getNumber());
          assert((Val != nullptr) &&
                 "Unexpected null value of implicit defined registers");
          CurCTInfo->RegValues.push_back(Val);
        }
      }
    }
    CurCTInfo->Raised = false;
    CTInfo.push_back(CurCTInfo);
  }
  return true;
}

bool X86MachineInstructionRaiser::instrNameStartsWith(const MachineInstr &MI,
                                                      StringRef name) const {
  return x86InstrInfo->getName(MI.getOpcode()).startswith(name);
}

// Return a new function which is the same in every respect except with
// specified return type.
void X86MachineInstructionRaiser::changeRaisedFunctionReturnType(Type *RetTy) {
  LLVMContext &Ctx = MF.getFunction().getContext();

  Type *FuncRetTy = raisedFunction->getReturnType();

  if (FuncRetTy != RetTy) {
    std::vector<Type *> ArgTypes;
    for (const Argument &I : raisedFunction->args())
      ArgTypes.push_back(I.getType());

    // Create function with new signature and clone the old body into it.
    auto NewFT = FunctionType::get(Type::getVoidTy(Ctx), ArgTypes, false);
    auto NewF = Function::Create(NewFT, raisedFunction->getLinkage(),
                                 raisedFunction->getAddressSpace(),
                                 raisedFunction->getName());
    NewF->copyAttributesFrom(raisedFunction);
    NewF->setSubprogram(raisedFunction->getSubprogram());

    raisedFunction->getParent()->getFunctionList().insert(
        raisedFunction->getIterator(), NewF);
    NewF->takeName(raisedFunction);

    NewF->getBasicBlockList().splice(NewF->begin(),
                                     raisedFunction->getBasicBlockList());
    // Loop over the argument list, transferring uses of the old arguments over
    // to the new arguments, also transferring over the names as well.
    for (Function::arg_iterator I = raisedFunction->arg_begin(),
                                E = raisedFunction->arg_end(),
                                I2 = NewF->arg_begin();
         I != E; ++I) {
      // Move the name and users over to the new version.
      I->replaceAllUsesWith(&*I2);
      I2->takeName(&*I);
      ++I2;
    }
    raisedFunction = NewF;
  }
  return;
}
