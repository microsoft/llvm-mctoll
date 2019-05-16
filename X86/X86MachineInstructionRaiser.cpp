//===-- X86MachineInstructionRaiser.cpp -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of X86MachineInstructionRaiser class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "X86MachineInstructionRaiser.h"
#include "ExternalFunctions.h"
#include "MachineFunctionRaiser.h"
#include "X86InstrBuilder.h"
#include "X86ModuleRaiser.h"
#include "X86RaisedValueTracker.h"
#include "X86RegisterUtils.h"
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

// Constructor

X86MachineInstructionRaiser::X86MachineInstructionRaiser(
    MachineFunction &machFunc, const ModuleRaiser *mr, MCInstRaiser *mcir)
    : MachineInstructionRaiser(machFunc, mr, mcir),
      machineRegInfo(MF.getRegInfo()),
      x86TargetInfo(MF.getSubtarget<X86Subtarget>()) {
  x86InstrInfo = x86TargetInfo.getInstrInfo();
  x86RegisterInfo = x86TargetInfo.getRegisterInfo();
  PrintPass =
      (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() > 0);
  FPUStack.TOP = 0;
  for (int i = 0; i < FPUSTACK_SZ; i++) {
    FPUStack.Regs[i] = nullptr;
  }
  raisedValues = nullptr;
}

/* Delete noop instructions */

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

static inline Type *getImmOperandType(const MachineInstr &mi,
                                      unsigned int OpIndex) {
  LLVMContext &llvmContext(mi.getMF()->getFunction().getContext());
  MachineOperand Op = mi.getOperand(OpIndex);
  assert(Op.isImm() && "Attempt to get size of non-immediate operand");
  // Initialize to nullptr - unknown
  Type *ImmType = nullptr;
  uint8_t ImmSize = X86II::getSizeOfImm(mi.getDesc().TSFlags);

  switch (ImmSize) {
  case 8:
    ImmType = Type::getInt64Ty(llvmContext);
    break;
  case 4:
    ImmType = Type::getInt32Ty(llvmContext);
    break;
  case 2:
    ImmType = Type::getInt16Ty(llvmContext);
    break;
  case 1:
    ImmType = Type::getInt8Ty(llvmContext);
    break;
  default:
    assert(false && "Immediate operand of unknown size");
    break;
  }
  return ImmType;
}

static inline uint8_t getPhysRegOperandSize(const MachineInstr &mi,
                                            unsigned int OpIndex) {
  MachineOperand Op = mi.getOperand(OpIndex);
  // Initialize to 0 - unknown
  uint8_t RegSize = 0;
  assert(Op.isReg() && "Attempt to get size of non-register operand");
  unsigned int RegNo = Op.getReg();
  if (TargetRegisterInfo::isPhysicalRegister(RegNo)) {
    if (is64BitPhysReg(RegNo))
      RegSize = 8;
    else if (is32BitPhysReg(RegNo))
      RegSize = 4;
    else if (is16BitPhysReg(RegNo))
      RegSize = 2;
    else if (is8BitPhysReg(RegNo))
      RegSize = 1;
    else
      assert(false && "Register operand of unknown register class");
  } else {
    assert(
        false &&
        "Failed to get operand type for unknown physical register specified");
  }
  return RegSize;
}

static inline Type *getPhysRegOperandType(const MachineInstr &mi,
                                          unsigned int OpIndex) {
  MachineOperand Op = mi.getOperand(OpIndex);
  // Initialize to nullptr - unknown
  Type *RegTy = nullptr;

  assert(Op.isReg() && "Attempt to get type of non-register operand");
  unsigned int RegNo = Op.getReg();
  LLVMContext &Ctx(mi.getMF()->getFunction().getContext());
  if (TargetRegisterInfo::isPhysicalRegister(RegNo)) {
    if (is64BitPhysReg(RegNo))
      RegTy = Type::getInt64Ty(Ctx);
    else if (is32BitPhysReg(RegNo))
      RegTy = Type::getInt32Ty(Ctx);
    else if (is16BitPhysReg(RegNo))
      RegTy = Type::getInt16Ty(Ctx);
    else if (is8BitPhysReg(RegNo))
      RegTy = Type::getInt8Ty(Ctx);
    else
      assert(false && "Register operand of unknown register class");
  } else {
    assert(
        false &&
        "Failed to get operand type for unknown physical register specified");
  }

  return RegTy;
}

static inline bool isPushToStack(const MachineInstr &mi) {
  unsigned char BaseOpcode = X86II::getBaseOpcodeFor(mi.getDesc().TSFlags);
  // Note : Encoding of PUSH [CS | DS | ES | SS | FS | GS] not checked.
  return ((BaseOpcode == 0x50) || (BaseOpcode == 0x6A) ||
          (BaseOpcode == 0x68) || (BaseOpcode == 0xFF) ||
          (BaseOpcode == 0x60) || (BaseOpcode == 0x9c));
}

static inline bool isPopFromStack(const MachineInstr &mi) {
  unsigned char BaseOpcode = X86II::getBaseOpcodeFor(mi.getDesc().TSFlags);
  // Note : Encoding of POP [DS | ES | SS | FS | GS] not checked.
  return ((BaseOpcode == 0x58) || (BaseOpcode == 0x8F) ||
          (BaseOpcode == 0x9D) || (BaseOpcode == 0x61) ||
          // or LEAVE
          (BaseOpcode == 0xC9));
}

static inline bool isEffectiveAddrValue(Value *val) {
  if (isa<LoadInst>(val)) {
    return true;
  } else if (isa<BinaryOperator>(val)) {
    BinaryOperator *binOpVal = dyn_cast<BinaryOperator>(val);
    if (binOpVal->isBinaryOp(BinaryOperator::Add) ||
        binOpVal->isBinaryOp(BinaryOperator::Mul)) {
      return true;
    }
  } else if (val->getType()->isIntegerTy() &&
             (val->getName().startswith("arg"))) {
    // Consider an argument of integer type to be an address value type.
    return true;
  }
  return false;
}

bool X86MachineInstructionRaiser::appendInstToBB(BasicBlock *RaisedBB,
                                                 Instruction *Inst) {
  return true;
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
//
bool X86MachineInstructionRaiser::hasPhysRegDefInBlock(
    int PhysReg, const MachineInstr *StartMI, const MachineBasicBlock *MBB,
    unsigned StopAtInstProp, bool &HasStopInst) {
  // Walk backwards starting from the instruction before StartMI
  MachineBasicBlock::const_reverse_iterator InstIter;
  HasStopInst = false; // default value
  if (StartMI == nullptr)
    InstIter = MBB->rend();
  else
    InstIter = StartMI->getReverseIterator();

  unsigned SuperReg = find64BitSuperReg(PhysReg);

  for (const MachineInstr &MI : make_range(++InstIter, MBB->rend())) {
    // Stop walking past the instruction with the specified property in the
    // block.
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
          if (TargetRegisterInfo::isPhysicalRegister(MOReg)) {
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
          // from the section that contains the virtual address symVirtualAddr.
          // In executable and shared object files, st_value holds a virtual
          // address.
          uint64_t SymbVal = 0;
          for (section_iterator SecIter : Elf64LEObjFile->sections()) {
            uint64_t SecStart = SecIter->getAddress();
            uint64_t SecEnd = SecStart + SecIter->getSize();
            if ((SecStart <= SymVirtualAddr) && (SecEnd >= SymVirtualAddr)) {
              // Get the initial symbol value only if this is not a bss section.
              // Else, symVal is already initialized to 0.
              if (SecIter->isBSS()) {
                Lnkg = GlobalValue::CommonLinkage;
              } else {
                StringRef SecData;
                SecIter->getContents(SecData);
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
          GlobalVal->setAlignment(Symb->st_size);
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
              StringRef SecData;
              SecIter->getContents(SecData);
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
        GlobalVal->setAlignment(SymAlignment);
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

unsigned int
X86MachineInstructionRaiser::find64BitSuperReg(unsigned int PhysReg) {
  unsigned int SuperReg;
  bool SuperRegFound = false;

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

  if (is64BitPhysReg(PhysReg)) {
    SuperReg = PhysReg;
    SuperRegFound = true;
  } else {
    for (MCSuperRegIterator SuperRegs(PhysReg, x86RegisterInfo);
         SuperRegs.isValid(); ++SuperRegs) {
      SuperReg = *SuperRegs;
      if (is64BitPhysReg(SuperReg)) {
        assert(SuperRegFound != true &&
               "Expect only one 64-bit super register");
        SuperRegFound = true;
      }
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

// Promote the ReachingValue of PhysReg defined in DefiningMBB to specified
// stack slot Alloca.
StoreInst *X86MachineInstructionRaiser::promotePhysregToStackSlot(
    int PhysReg, Value *ReachingValue, int DefiningMBB, AllocaInst *Alloca) {
  StoreInst *StInst = nullptr;
  LLVMContext &Ctxt(MF.getFunction().getContext());

  // Make sure PhysReg is converted to SuperReg
  int SuperReg = find64BitSuperReg(PhysReg);
  assert((ReachingValue != nullptr) &&
         "Null incoming value of reaching definition found");
  assert(raisedValues->getInBlockPhysRegDefVal(SuperReg, DefiningMBB) ==
             ReachingValue &&
         "Inconsistent reaching defined value found");
  assert(ReachingValue->getType()->isIntegerTy() &&
         "Unhandled stack promotion of non-integer defined type");
  // Prepare to store this value in stack location.
  // Get the size of defined physical register
  int DefinedPhysRegSzInBits =
      raisedValues->getInBlockPhysRegSize(SuperReg, DefiningMBB);
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
  if (DefinedPhysRegSzInBits != StackLocSzInBits) {
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
  if (reachingDefsToPromote.size() > 0) {
    for (auto RDToFix : reachingDefsToPromote) {
      unsigned int SuperReg = find64BitSuperReg(std::get<0>(RDToFix));
      unsigned int DefiningMBBNo = std::get<1>(RDToFix);
      Value *Val = std::get<2>(RDToFix);
      assert((isa<AllocaInst>(Val)) &&
             "Found value that is not a stack location "
             "during reaching definition fixup");
      AllocaInst *Alloca = dyn_cast<AllocaInst>(Val);
      Value *ReachingDef =
          raisedValues->getInBlockPhysRegDefVal(SuperReg, DefiningMBBNo);
      assert((ReachingDef != nullptr) &&
             "Null reaching definition found during reaching definition fixup");
      StoreInst *StInst = promotePhysregToStackSlot(SuperReg, ReachingDef,
                                                    DefiningMBBNo, Alloca);
      assert(StInst != nullptr && "Failed to promote register to memory");
    }
  }
  return true;
}
Value *X86MachineInstructionRaiser::getStackAllocatedValue(
    const MachineInstr &mi, X86AddressMode &memRef, bool isStackPointerAdjust) {
  unsigned int stackFrameIndex;

  assert((memRef.BaseType == X86AddressMode::RegBase) &&
         "Register type operand expected for stack allocated value lookup");
  unsigned PReg = find64BitSuperReg(memRef.Base.Reg);
  assert(((PReg == X86::RSP) || (PReg == X86::RBP)) &&
         "Stack or base pointer expected for stack allocated value lookup");
  Value *CurSPVal = getRegOrArgValue(PReg, mi.getParent()->getNumber());

  // If the memory reference offset is 0 i.e., not different from the current sp
  // reference and there is already a stack allocation, just return that value
  if ((memRef.Disp == 0) && (CurSPVal != nullptr)) {
    return CurSPVal;
  }
  // At this point, the stack offset specified in the memory opernad is
  // different from that if the alloca corresponding to sp or there is no stack
  // allocation corresponding to sp.
  int NewDisp;
  MachineFrameInfo &MFrameInfo = MF.getFrameInfo();
  // If there is no allocation corresponding to sp, set the offset of new
  // allocation to be that specified in memory operand.
  if (CurSPVal == nullptr) {
    NewDisp = memRef.Disp;
  } else {
    assert((memRef.Disp != 0) && "Unexpected 0 offset value");
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
    NewDisp = MFrameInfo.getObjectOffset(StackIndex - 1) + memRef.Disp;
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
  unsigned stackObjectSize = getInstructionMemOpSize(mi.getOpcode());
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
  AllocaInst *alloca = new AllocaInst(Ty, allocaAddrSpace, 0, typeAlignment,
                                      isStackPointerAdjust ? "StackAdj" : "");

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
      if (SecIter->getName(SecName)) {
        assert(false && "Failed to get section name with PLT offset");
      }
      if (SecName.compare(".plt") != 0) {
        assert(false && "Unexpected section name of PLT offset");
      }
      StringRef SecData;
      SecIter->getContents(SecData);
      // StringRef BytesStr;
      //    error(Section.getContents(BytesStr));
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
      CalledFunc = MR->getFunctionAt(CalledFuncSymAddr.get());

      if (CalledFunc == nullptr) {
        // This is an undefined function symbol. Look through the list of
        // known glibc interfaces and construct a Function accordingly.
        CalledFunc =
            ExternalFunctions::Create(*CalledFuncSymName, *(MR->getModule()));
      }
      // Found the section we are looking for
      break;
    }
  }
  return CalledFunc;
}

// Return a global value corresponding to read-only  data.
const Value *X86MachineInstructionRaiser::getOrCreateGlobalRODataValueAtOffset(
    int64_t Offset, Type *OffsetTy1) {
  // A negative offset implies that this is not an offset into ro-data
  // section. Just return nullptr.
  if (Offset < 0) {
    return nullptr;
  }
  const Value *RODataValue = MR->getRODataValueAt(Offset);
  if (RODataValue == nullptr) {
    // Only if the imm value is a positive value
    const ELF64LEObjectFile *Elf64LEObjFile =
        dyn_cast<ELF64LEObjectFile>(MR->getObjectFile());
    assert(Elf64LEObjFile != nullptr &&
           "Only 64-bit ELF binaries supported at present.");
    LLVMContext &llvmContext(MF.getFunction().getContext());
    // Check if this is an address in .rodata
    for (section_iterator SecIter : Elf64LEObjFile->sections()) {
      uint64_t SecStart = SecIter->getAddress();
      uint64_t SecEnd = SecStart + SecIter->getSize();
      // We know that SrcImm is a positive value. So, casting it is OK.
      if ((SecStart <= (uint64_t)Offset) && (SecEnd >= (uint64_t)Offset)) {
        if (SecIter->isData()) {
          StringRef SecData;
          SecIter->getContents(SecData);
          unsigned DataOffset = Offset - SecStart;
          const unsigned char *RODataBegin = SecData.bytes_begin() + DataOffset;
          StringRef ROStringRef(reinterpret_cast<const char *>(RODataBegin));
          Constant *StrConstant =
              ConstantDataArray::getString(llvmContext, ROStringRef);
          auto GlobalStrConstVal = new GlobalVariable(
              *(MR->getModule()), StrConstant->getType(), true /* isConstant */,
              GlobalValue::PrivateLinkage, StrConstant, "RO-String");
          GlobalStrConstVal->setAlignment(1);
          // Record the mapping between offset and global value
          MR->addRODataValueAt(GlobalStrConstVal, Offset);
          RODataValue = GlobalStrConstVal;
        } else if (SecIter->isBSS()) {
          // Get symbol name associated with the address
          // Find symbol at Offset
          SymbolRef GlobalDataSym;
          for (auto Symbol : Elf64LEObjFile->symbols()) {
            if (Symbol.getELFType() == ELF::STT_OBJECT) {
              auto SymAddr = Symbol.getAddress();
              assert(SymAddr && "Failed to lookup symbol for global address");
              uint64_t SymAddrVal = SymAddr.get();
              // We have established that Offset is not negative above.
              // So, OK to cast. Check if the memory address Offset is
              // SymAddrVal
              if (SymAddrVal == (unsigned)Offset) {
                GlobalDataSym = Symbol;
                break;
              }
            }
          }
          assert((GlobalDataSym.getObject() != nullptr) &&
                 "Failed to find symbol for global address.");
          Expected<StringRef> GlobalDataSymName = GlobalDataSym.getName();
          assert(GlobalDataSymName &&
                 "Failed to find symbol name for global address");
          // Find if a global value associated with symbol name is
          // already created
          for (GlobalVariable &gv : MR->getModule()->globals()) {
            if (gv.getName().compare(GlobalDataSymName.get()) == 0) {
              RODataValue = &gv;
            }
          }
          if (RODataValue == nullptr) {
            auto symb =
                Elf64LEObjFile->getSymbol(GlobalDataSym.getRawDataRefImpl());
            uint64_t symbSize = symb->st_size;
            GlobalValue::LinkageTypes linkage;
            switch (symb->getBinding()) {
            case ELF::STB_GLOBAL:
              // Note that this is a symbol in BSS
              linkage = GlobalValue::CommonLinkage;
              break;
            default:
              assert(false && "Unhandled global symbol binding type");
            }
            // By default, the symbol alignment is the symbol section
            // alignment. Will be adjusted as needed based on the size of
            // the symbol later.
            auto GlobalDataSymSection = GlobalDataSym.getSection();
            assert(GlobalDataSymSection &&
                   "No section for global symbol found");
            uint64_t GlobDataSymSectionAlignment =
                GlobalDataSymSection.get()->getAlignment();
            // Make sure the alignment is a power of 2
            assert(((GlobDataSymSectionAlignment &
                     (GlobDataSymSectionAlignment - 1)) == 0) &&
                   "Section alignment not a power of 2");
            // If symbol size is less than symbol section size, set
            // alignment to symbol size.
            if (symbSize < GlobDataSymSectionAlignment) {
              GlobDataSymSectionAlignment = symbSize;
            }
            // symbSize is in number of bytes
            Type *GlobalValTy = Type::getInt8Ty(llvmContext);
            Constant *GlobalInit = nullptr;
            if (symbSize > GlobDataSymSectionAlignment) {
              GlobalValTy = ArrayType::get(GlobalValTy, symbSize);
              GlobalInit = ConstantAggregateZero::get(GlobalValTy);
            } else {
              GlobalInit = ConstantInt::get(GlobalValTy, 0);
            }
            auto GlobalVal = new GlobalVariable(
                *(MR->getModule()), GlobalValTy, false /* isConstant */,
                linkage, GlobalInit, GlobalDataSymName.get());
            GlobalVal->setAlignment(GlobDataSymSectionAlignment);
            GlobalVal->setDSOLocal(true);
            RODataValue = GlobalVal;
          }
        }
        break;
      }
    }
  }
  return RODataValue;
}

// Return a value corresponding to global symbol at Offset referenced in
// MachineInst mi.
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
    GlobalVariableValue =
        const_cast<Value *>(getOrCreateGlobalRODataValueAtOffset(
            Offset, Type::getInt64Ty(MF.getFunction().getContext())));
  } else {
    // If Offset corresponds to a global symbol, materialize a global variable.
    unsigned MemAccessSizeInBytes = getInstructionMemOpSize(MI.getOpcode());
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

      // get the initial value of the global data symbol at symVirtualAddr
      // from the section that contains the virtual address symVirtualAddr.
      // In executable and shared object files, st_value holds a virtual
      // address.
      SmallVector<Constant *, 32> ConstantVec;
      bool isBSSSymbol = false;
      for (section_iterator SecIter : Elf64LEObjFile->sections()) {
        uint64_t SecStart = SecIter->getAddress();
        uint64_t SecEnd = SecStart + SecIter->getSize();
        if ((SecStart <= SymVirtualAddr) && (SecEnd >= SymVirtualAddr)) {
          // Get the initial symbol value only if this is not a bss section.
          // Else, symVal is already initialized to 0.
          if (SecIter->isBSS()) {
            Lnkg = GlobalValue::CommonLinkage;
            isBSSSymbol = true;
          } else {
            StringRef SecData;
            SecIter->getContents(SecData);
            unsigned Index = SymVirtualAddr - SecStart;
            const char *beg =
                reinterpret_cast<const char *>(SecData.bytes_begin() + Index);

            // Symbol size should atleast be the same as memory access size of
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
                const Value *RoDataValue = getOrCreateGlobalRODataValueAtOffset(
                    SymArrayElem, Type::getIntNTy(Ctx, MemAccessSizeInBytes));
                // If the SymArrElem does not correspond to an .rodata address
                // consider it to be data.
                if (RoDataValue == nullptr) {
                  Constant *ConstVal = ConstantInt::get(
                      Ctx, APInt(MemAccessSizeInBytes * 8, SymArrayElem));
                  ConstantVec.push_back(ConstVal);
                } else {
                  // If SymArrElem corresponds to an .rodata address,
                  // prepare the indices to this value to be used in the array
                  // representing the symbol value.
                  Value *GVValue = const_cast<Value *>(RoDataValue);
                  GlobalVariable *GV = dyn_cast<GlobalVariable>(GVValue);
                  Constant *Idx[2] = {
                      ConstantInt::get(Ctx, APInt(MemAccessSizeInBytes * 8, 0)),
                      ConstantInt::get(Ctx, APInt(MemAccessSizeInBytes * 8, 0)),
                  };
                  Constant *GEP = ConstantExpr::getInBoundsGetElementPtr(
                      GV->getValueType(), GV, Idx);
                  ConstantVec.push_back(GEP);
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

          // Change the global value type to byte type to indicate that the data
          // is interpreted as bytes.
          GlobalValTy = GlobalArrValTy;
        }
      } else {
        // Default initial value of global variable
        uint64_t SV = 0;
        assert(SymbSize == MemAccessSizeInBytes && "Inconsistent symbol sizes");

        if (ConstantVec.size() > 0) {
          assert(ConstantVec.size() == 1 &&
                 "Inconsistent symbol values of global symbol found");
          // Get the value read
          ConstantInt *CIV = dyn_cast<ConstantInt>(ConstantVec[0]);
          assert(CIV != nullptr && "Unexpected global value type");
          SV = CIV->getValue().getSExtValue();
        }
        GlobalInit = ConstantInt::get(GlobalValTy, SV);
      }

      // Now, create the global variable for the symbol at given Offset.
      auto GlobalVal = new GlobalVariable(
          *(MR->getModule()), GlobalValTy, false /* isConstant */, Lnkg,
          GlobalInit, GlobalDataSymNameIndexStrRef);
      GlobalVal->setAlignment(GlobDataSymAlignment);
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

  // Non-stack memory address is supported by this function.
  uint64_t BaseSupReg = find64BitSuperReg(BaseReg);
  assert((BaseSupReg != x86RegisterInfo->getStackRegister()) &&
         (BaseSupReg != x86RegisterInfo->getFramePtr()) &&
         "Not yet supported: Abstraction of value representing stack-based "
         "address expression");
  // IndexReg * ScaleAmt
  // Generate mul scaleAmt, IndexRegVal, if IndexReg is not 0.
  if (IndexReg != X86::NoRegister) {
    Value *IndexRegVal =
        getRegOrArgValue(IndexReg, MI.getParent()->getNumber());
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
          BinaryOperator::CreateMul(ScaleAmtValue, IndexRegVal);
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
      if (BaseRegVal->getType() != MemrefValue->getType()) {
        Instruction *CastMemrefValInst = CastInst::Create(
            CastInst::getCastOpcode(BaseRegVal, false, MemrefValue->getType(),
                                    false),
            BaseRegVal, MemrefValue->getType());
        RaisedBB->getInstList().push_back(CastMemrefValInst);
        BaseRegVal = CastMemrefValInst;
      }
      Instruction *AddInst = BinaryOperator::CreateAdd(BaseRegVal, MemrefValue);
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
                    // Index value not zero. So, scale it up by multiplying with
                    // GlobGEPSrcTySzInBytes, since the we are changing the
                    // access to byte array access.
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
                  // Cast the byte access GEP to MemrefValue type as needed
                  if (MemrefValue->getType() != ByteAccessGEP->getType()) {
                    CastInst *CInst = CastInst::Create(
                        CastInst::getCastOpcode(ByteAccessGEP, false,
                                                MemrefValue->getType(), false),
                        ByteAccessGEP, MemrefValue->getType());
                    RaisedBB->getInstList().push_back(CInst);
                    ByteAccessGEP = CInst;
                  }
                  DispValue = ByteAccessGEP;
                } else {
                  // Global GEP is already a byte array.
                  DispValue = GlobGEP;
                }
              } else {
                assert(false && "Unhandled situation where global symbol GEP "
                                "is not an array");
              }
            } else {
              assert(false && "Unhandled situation where global symbol GEP is "
                              "not inbounds");
            }
          }
        } else {
          assert(
              false &&
              "Unhandled situation where global symbol not accessed via GEP");
        }
      }
      // Generate add memrefVal, Disp.
      Instruction *AddInst = BinaryOperator::CreateAdd(MemrefValue, DispValue);
      RaisedBB->getInstList().push_back(AddInst);
      MemrefValue = AddInst;
      //}
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
// register. This function calls getRegValue() and generates a cast
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
    if (PRegTy != PRegValue->getType()) {
      // Get the BasicBlock corresponding to MachineBasicBlock of MI.
      BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
      Instruction *CInst = CastInst::Create(
          CastInst::getCastOpcode(PRegValue, false, PRegTy, false), PRegValue,
          PRegTy);
      RaisedBB->getInstList().push_back(CInst);
      PRegValue = CInst;
    }
  }
  return PRegValue;
}

// Get the 64-bit super register of PhysReg. Return PhysReg is it is
// a 64-bit register.
// Add a new PhysReg-Val pair if no mapping for PhysReg exists
// Replace the mapping to PhysReg-Val if one already exists.
Type *
X86MachineInstructionRaiser::getReturnTypeFromMBB(MachineBasicBlock &MBB) {
  Type *returnType = nullptr;

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
      // Check if any of RAX, EAX, AX or AL are defined
      if (I->getDesc().getNumDefs() != 0) {
        const MachineOperand &MO = I->getOperand(0);
        if (!MO.isReg()) {
          continue;
        }
        unsigned PReg = MO.getReg();
        if (!TargetRegisterInfo::isPhysicalRegister(PReg)) {
          continue;
        }
        if (PReg == X86::RAX) {
          if (returnType == nullptr) {
            returnType = Type::getInt64Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 64 &&
                   "Inconsistency while discovering return type");
          }
        } else if (PReg == X86::EAX) {
          if (returnType == nullptr) {
            returnType = Type::getInt32Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 32 &&
                   "Inconsistency while discovering return type");
          }
        } else if (PReg == X86::AX) {
          if (returnType == nullptr) {
            returnType = Type::getInt16Ty(MF.getFunction().getContext());
            break;
          } else {
            assert(returnType->isIntegerTy() &&
                   returnType->getScalarSizeInBits() == 16 &&
                   "Inconsistency while discovering return type");
          }
        } else if (PReg == X86::AL) {
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
  return returnType;
}

Type *X86MachineInstructionRaiser::getFunctionReturnType() {
  Type *returnType = nullptr;
  SmallVector<MachineBasicBlock *, 8> WorkList;
  BitVector BlockVisited(MF.getNumBlockIDs(), false);

  assert(x86TargetInfo.is64Bit() && "Only x86_64 binaries supported for now");

  // Find a return block. It is sufficient to get the dominator tree path
  // whose leaf is one of the return blocks to find the return type. This
  // type should be the same on any of the dominator paths from entry to
  // return block.
  MachineBasicBlock *RetBlock = nullptr;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.isReturnBlock()) {
      RetBlock = &MBB;
      break;
    }
  }

  if (RetBlock != nullptr)
    WorkList.push_back(RetBlock);

  while (!WorkList.empty()) {
    MachineBasicBlock *N = WorkList.pop_back_val();
    assert(!BlockVisited[N->getNumber()] &&
           "Encountered previously visited block");
    // Mark block as visited
    BlockVisited.set(N->getNumber());
    returnType = getReturnTypeFromMBB(*N);
    if (returnType != nullptr)
      return returnType;

    for (auto P : N->predecessors()) {
      // When a BasicBlock has the same predecessor and successor,
      // push_back the block which was not visited.
      if (!BlockVisited[P->getNumber()])
        WorkList.push_back(P);
    }
  }
  return nullptr;
}

// Construct prototype of the Function for the MachineFunction being raised.
FunctionType *X86MachineInstructionRaiser::getRaisedFunctionPrototype() {

  if (raisedFunction == nullptr) {
    // Cleanup NOOP instructions from all MachineBasicBlocks
    deleteNOOPInstrMF();

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

        // xor reg, reg is a typical idiom used to clear reg. If reg happens to
        // be an argument register, it should not be considered as such. Record
        // it as such.
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
    // If we are unable to discover the return type assume that the return
    // type is void.
    // TODO : Refine this once support is added to discover arguments passed
    // on the stack??
    if (returnType == nullptr)
      returnType = Type::getVoidTy(MF.getFunction().getContext());

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
  // Avoid using BasicBlock InstrList iterators so that the tool can
  // use LLVM built with LLVM_ABI_BREAKING_CHECKS ON or OFF.
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

// Check the sizes of the operand register at SrcOpindex and that of the
// corresponding SSA value. Return a value that is either truncated or
// sign-extended version of the SSA Value if their sizes do not match.
// Return the SSA value of the operand register at SrcOpindex, if they
// match. This is handles the situation following pattern of instructions
//   rax <- ...
//   edx <- opcode eax, ...

Value *
X86MachineInstructionRaiser::matchSSAValueToSrcRegSize(const MachineInstr &MI,
                                                       unsigned SrcOpIndex) {
  unsigned SrcOpSize = getPhysRegOperandSize(MI, SrcOpIndex);
  Value *SrcOpValue = getRegOrArgValue(MI.getOperand(SrcOpIndex).getReg(),
                                       MI.getParent()->getNumber());
  const DataLayout &dataLayout = MR->getModule()->getDataLayout();

  // Generate the appropriate cast instruction if the sizes of the current
  // source value and that of the source register do not match.
  uint64_t SrcValueSize =
      dataLayout.getTypeSizeInBits(SrcOpValue->getType()) / sizeof(uint64_t);

  assert(SrcValueSize <= sizeof(uint64_t) && SrcOpSize <= sizeof(uint64_t) &&
         "Unexpected source Value size in move instruction");

  if (SrcOpSize != SrcValueSize) {
    // Get the BasicBlock corresponding to MachineBasicBlock of MI.
    BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());
    Type *CastTy = getPhysRegOperandType(MI, SrcOpIndex);
    CastInst *CInst = CastInst::Create(
        CastInst::getCastOpcode(SrcOpValue, false, CastTy, false), SrcOpValue,
        CastTy);
    RaisedBB->getInstList().push_back(CInst);
    SrcOpValue = CInst;
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

bool X86MachineInstructionRaiser::raisePushInstruction(const MachineInstr &mi) {
  const MCInstrDesc &MCIDesc = mi.getDesc();
  uint64_t MCIDTSFlags = MCIDesc.TSFlags;

  if ((MCIDTSFlags & X86II::FormMask) == X86II::AddRegFrm) {
    // This is a register PUSH. If the source is register, create a slot on
    // the stack.
    if (mi.getOperand(0).isReg()) {
      const DataLayout &DL = MR->getModule()->getDataLayout();
      unsigned AllocaAddrSpace = DL.getAllocaAddrSpace();

      // Create alloca instruction to allocate stack slot
      Type *Ty = getPhysRegOperandType(mi, 0);
      AllocaInst *Alloca =
          new AllocaInst(Ty, AllocaAddrSpace, 0, DL.getPrefTypeAlignment(Ty));

      // Create a stack slot associated with the alloca instruction
      unsigned int StackFrameIndex = MF.getFrameInfo().CreateStackObject(
          (Ty->getPrimitiveSizeInBits() / 8), DL.getPrefTypeAlignment(Ty),
          false /* isSpillSlot */, Alloca);

      // Compute size of new stack object.
      const MachineFrameInfo &MFI = MF.getFrameInfo();
      // Size of currently allocated object size
      int64_t ObjectSize = MFI.getObjectSize(StackFrameIndex);
      // Size of object at previous index; 0 if this is the first object on
      // stack.
      int64_t PrevObjectSize =
          (StackFrameIndex != 0) ? MFI.getObjectOffset(StackFrameIndex - 1) : 0;
      int64_t Offset = PrevObjectSize - ObjectSize;

      // Set object size.
      MF.getFrameInfo().setObjectOffset(StackFrameIndex, Offset);

      // Add the alloca instruction to entry block
      insertAllocaInEntryBlock(Alloca);
      // The alloca corresponds to the current location of stack pointer
      raisedValues->setPhysRegSSAValue(X86::RSP, mi.getParent()->getNumber(),
                                       Alloca);
      return true;
    } else {
      assert(false && "Unhandled PUSH instruction with a non-register operand");
    }
  } else {
    assert(false && "Unhandled PUSH instruction with source operand other "
                    "than AddrRegFrm");
  }
  return false;
}

bool X86MachineInstructionRaiser::raisePopInstruction(const MachineInstr &mi) {
  // TODO : Need to handle pop instructions other than those that restore bp
  // from stack.
  const MCInstrDesc &MCIDesc = mi.getDesc();
  uint64_t MCIDTSFlags = MCIDesc.TSFlags;

  if ((MCIDTSFlags & X86II::FormMask) == X86II::AddRegFrm) {
    // This is a register POP. If the source is base pointer,
    // not need to raise the instruction.
    if (mi.definesRegister(X86::RBP) || mi.definesRegister(X86::EBP)) {
      return true;
    } else {
      // assert(false && "Unhandled POP instruction that restores a register
      // "
      //                "other than frame pointer");
      return true;
    }
  } else {
    if (getInstructionKind(mi.getOpcode()) == InstructionKind::LEAVE_OP) {
      return true;
    }
    assert(false && "Unhandled POP instruction with source operand other "
                    "than AddrRegFrm");
  }
  return false;
}

bool X86MachineInstructionRaiser::raiseConvertBWWDDQMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();
  LLVMContext &llvmContext(MF.getFunction().getContext());

  assert(MIDesc.getNumImplicitUses() == 1 && MIDesc.getNumImplicitDefs() == 1 &&
         "Unexpected number of implicit uses and defs in cbw/cwde/cdqe "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  MCPhysReg UseReg = MIDesc.ImplicitUses[0];
  MCPhysReg DefReg = MIDesc.ImplicitDefs[0];
  Type *TargetTy = nullptr;

  if (Opcode == X86::CDQE) {
    assert(is32BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cdqe instruction");
    assert(is64BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cdqe instruction");
    TargetTy = Type::getInt64Ty(llvmContext);
  } else if (Opcode == X86::CBW) {
    assert(is8BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cbw instruction");
    assert(is16BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cbw instruction");
    TargetTy = Type::getInt16Ty(llvmContext);
  } else if (Opcode == X86::CWDE) {
    assert(is16BitPhysReg(UseReg) &&
           "Unexpected non-32-bit register in cwde instruction");
    assert(is32BitPhysReg(DefReg) &&
           "Unexpected non-64-bit register in cwde instruction");
    TargetTy = Type::getInt32Ty(llvmContext);
  }
  assert(TargetTy != nullptr &&
         "Target type not set for cbw/cwde/cdqe instruction");
  Value *UseValue = getRegOrArgValue(UseReg, MI.getParent()->getNumber());

  // Generate sign-extend instruction
  SExtInst *SextInst = new SExtInst(UseValue, TargetTy);
  RaisedBB->getInstList().push_back(SextInst);

  // Update the value mapping of DefReg
  raisedValues->setPhysRegSSAValue(DefReg, MI.getParent()->getNumber(),
                                   SextInst);
  return true;
}

bool X86MachineInstructionRaiser::raiseConvertWDDQQOMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();
  LLVMContext &Ctx(MF.getFunction().getContext());

  assert(MIDesc.getNumImplicitUses() == 1 && MIDesc.getNumImplicitDefs() == 2 &&
         "Unexpected number of implicit uses and defs in cwd/cdq/cqo "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  MCPhysReg UseReg = MIDesc.ImplicitUses[0];
  MCPhysReg DefReg_0 = MIDesc.ImplicitDefs[0];
  MCPhysReg DefReg_1 = MIDesc.ImplicitDefs[1];
  Type *TargetTy = nullptr;
  Type *UseRegTy = nullptr;

  if (Opcode == X86::CWD) {
    assert(is16BitPhysReg(UseReg) && is16BitPhysReg(DefReg_0) &&
           is16BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cwd "
           "instruction");
    TargetTy = Type::getInt32Ty(Ctx);
    UseRegTy = Type::getInt16Ty(Ctx);
  } else if (Opcode == X86::CDQ) {
    assert(is32BitPhysReg(UseReg) && is32BitPhysReg(DefReg_0) &&
           is32BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cdq "
           "instruction");
    TargetTy = Type::getInt64Ty(Ctx);
    UseRegTy = Type::getInt32Ty(Ctx);
  } else if (Opcode == X86::CQO) {
    assert(is64BitPhysReg(UseReg) && is16BitPhysReg(DefReg_0) &&
           is64BitPhysReg(DefReg_1) && (UseReg == DefReg_0) &&
           "Unexpected characteristics of use/def registers in cdo "
           "instruction");
    TargetTy = Type::getInt128Ty(Ctx);
    UseRegTy = Type::getInt64Ty(Ctx);
  }

  assert((TargetTy != nullptr) && (UseRegTy != nullptr) &&
         "Target type not set for cwd/cdq/cqo instruction");
  Value *UseValue = getRegOrArgValue(UseReg, MI.getParent()->getNumber());

  // Generate sign-extend instruction
  SExtInst *TargetSextInst = new SExtInst(UseValue, TargetTy);
  assert(UseValue->getType()->getScalarSizeInBits() ==
             UseRegTy->getScalarSizeInBits() &&
         "Mismatched types in cwd/cdq/cqo instruction");
  RaisedBB->getInstList().push_back(TargetSextInst);

  // Logical Shift TargetSextInst by n-bits (where n is the size of
  // UserRegTy) to get the high bytes and set DefReg_1 to the resulting
  // value.
  Value *ShiftAmount = ConstantInt::get(
      TargetTy, UseRegTy->getScalarSizeInBits(), false /* isSigned */);
  Instruction *LShrInst =
      BinaryOperator::CreateLShr(TargetSextInst, ShiftAmount);
  RaisedBB->getInstList().push_back(LShrInst);
  // Truncate LShrInst to get the high bytes
  Instruction *HighBytesInst =
      CastInst::Create(Instruction::Trunc, LShrInst, UseRegTy);
  RaisedBB->getInstList().push_back(HighBytesInst);
  // Update the value mapping of DefReg_1
  raisedValues->setPhysRegSSAValue(DefReg_1, MI.getParent()->getNumber(),
                                   HighBytesInst);

  return true;
}

bool X86MachineInstructionRaiser::raiseMoveImmToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  bool success = false;

  switch (Opcode) {
  case X86::MOV8ri:
  case X86::MOV16ri:
  case X86::MOV32ri:
  case X86::MOV64ri: {
    unsigned DestOpIndex = 0, SrcOpIndex = 1;
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    const MachineOperand &SrcOp = MI.getOperand(SrcOpIndex);
    assert(MI.getNumExplicitOperands() == 2 && DestOp.isReg() &&
           SrcOp.isImm() &&
           "Expecting exactly two operands for move imm-to-reg instructions");

    unsigned int DstPReg = DestOp.getReg();
    int64_t SrcImm = SrcOp.getImm();

    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DestOpIndex);

    Type *ImmTy = getImmOperandType(MI, 1);
    Value *srcValue = nullptr;

    assert(DstPRegSize ==
               (ImmTy->getPrimitiveSizeInBits() / sizeof(uint64_t)) &&
           "Mismatched imm and dest sizes in move imm to reg instruction.");
    srcValue = ConstantInt::get(ImmTy, SrcImm);
    // Update the value mapping of dstReg
    raisedValues->setPhysRegSSAValue(DstPReg, MI.getParent()->getNumber(),
                                     srcValue);
    success = true;
  } break;
  default:
    assert(false && "Unhandled move imm-to-reg instruction");
    break;
  }
  return success;
}

bool X86MachineInstructionRaiser::raiseMoveRegToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  int MBBNo = MI.getParent()->getNumber();
  LLVMContext &Ctx(MF.getFunction().getContext());

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  bool Success = false;
  unsigned DstIndex = 0;
  unsigned Src1Index = 1;
  unsigned Src2Index = 2;
  assert(
      (MI.getNumExplicitOperands() == 2 || MI.getNumExplicitOperands() == 4) &&
      MI.getOperand(DstIndex).isReg() &&
      (MI.getOperand(Src1Index).isReg() || MI.getOperand(Src2Index).isReg()) &&
      "Expecting exactly two or four operands for move reg-to-reg "
      "instructions");

  unsigned int DstPReg = MI.getOperand(DstIndex).getReg();

  // Get source operand value
  Value *SrcValue = nullptr;
  if (MI.getNumExplicitOperands() == 2)
    SrcValue = getRegOperandValue(MI, Src1Index);
  else if (MI.getNumExplicitOperands() == 4)
    SrcValue = getRegOperandValue(MI, Src2Index);
  else
    assert(false &&
           "Unexpected operand numbers for move reg-to-reg instruction");

  switch (Opcode) {
  case X86::MOVSX16rr8:
  case X86::MOVSX32rr8:
  case X86::MOVSX32rr16:
  case X86::MOVSX64rr8:
  case X86::MOVSX64rr16:
  case X86::MOVSX64rr32:
  case X86::MOVZX16rr8:
  case X86::MOVZX32rr8:
  case X86::MOVZX32rr16:
  case X86::MOVZX64rr8:
  case X86::MOVZX64rr16: {
    Type *Ty = nullptr;
    Instruction::CastOps Cast;
    // Check for sanity of source value
    assert(SrcValue &&
           "Encountered instruction with undefined source register");

    switch (Opcode) {
    case X86::MOVSX16rr8: {
      assert(is16BitPhysReg(DstPReg) &&
             "Not found expected 16-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt16Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVSX32rr8:
    case X86::MOVSX32rr16: {
      assert(is32BitPhysReg(DstPReg) &&
             "Not found expected 32-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt32Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVSX64rr8:
    case X86::MOVSX64rr16:
    case X86::MOVSX64rr32: {
      assert(is64BitPhysReg(DstPReg) &&
             "Not found expected 64-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt64Ty(Ctx);
      Cast = Instruction::SExt;
    } break;
    case X86::MOVZX16rr8: {
      assert(is16BitPhysReg(DstPReg) &&
             "Not found expected 16-bit destination register - movsx "
             "instruction");
      Ty = Type::getInt16Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    case X86::MOVZX32rr8:
    case X86::MOVZX32rr16: {
      assert(is32BitPhysReg(DstPReg) &&
             "Not found expected 32-bit destination register - movzx "
             "instruction");
      Ty = Type::getInt32Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    case X86::MOVZX64rr8:
    case X86::MOVZX64rr16: {
      assert(is64BitPhysReg(DstPReg) &&
             "Not found expected 64-bit destination register - movzx "
             "instruction");
      Ty = Type::getInt64Ty(Ctx);
      Cast = Instruction::ZExt;
    } break;
    default:
      assert(false &&
             "Should not reach here! - mov with extension instruction");
    }
    assert(Ty != nullptr &&
           "Failed to set type - mov with extension instruction");
    // Now create the cast instruction corresponding to the instruction.
    CastInst *CInst = CastInst::Create(Cast, SrcValue, Ty);
    RaisedBB->getInstList().push_back(CInst);

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, CInst);
    Success = true;
  } break;
  case X86::MOV64rr:
  case X86::MOV32rr:
  case X86::MOV16rr:
  case X86::MOV8rr: {
    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
    unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src1Index);

    // Verify sanity of the instruction.
    assert(DstPRegSize != 0 && DstPRegSize == SrcPRegSize &&
           "Unexpected sizes of source and destination registers size differ "
           "in mov instruction");
    assert(SrcValue &&
           "Encountered mov instruction with undefined source register");
    assert(SrcValue->getType()->isSized() &&
           "Unsized source value in move instruction");
    SrcValue = matchSSAValueToSrcRegSize(MI, Src1Index);

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SrcValue);
    Success = true;
  } break;
  case X86::CMOV16rr:
  case X86::CMOV32rr:
  case X86::CMOV64rr: {
    unsigned int DstPRegSize = getPhysRegOperandSize(MI, DstIndex);
    unsigned int SrcPRegSize = getPhysRegOperandSize(MI, Src2Index);

    // Verify sanity of the instruction.
    assert(DstPRegSize != 0 && DstPRegSize == SrcPRegSize &&
           "Unexpected sizes of source and destination registers size differ "
           "in cmovcc instruction");
    assert(SrcValue &&
           "Encountered cmovcc instruction with undefined source register");
    assert(SrcValue->getType()->isSized() &&
           "Unsized source value in cmovcc instruction");
    SrcValue = matchSSAValueToSrcRegSize(MI, Src2Index);

    // Get destination operand value
    Value *DstValue = getRegOrArgValue(DstPReg, MBBNo);
    Value *TrueValue = ConstantInt::getTrue(Ctx);
    Value *FalseValue = ConstantInt::getFalse(Ctx);
    CmpInst::Predicate Pred = CmpInst::Predicate::BAD_ICMP_PREDICATE;
    Value *CMOVCond = nullptr;

    switch (X86::getCondFromCMov(MI)) {
    case X86::COND_NE: {
      // Check if ZF == 0
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising CMOVNE!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      CMOVCond = new ICmpInst(Pred, ZFValue, FalseValue, "Cond_CMOVNE");
    } break;
    case X86::COND_E: {
      // Check if ZF == 1
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising CMOVE!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      CMOVCond = new ICmpInst(Pred, ZFValue, TrueValue, "Cond_CMOVE");
    } break;
    case X86::COND_A: {
      // Check CF == 0 and ZF == 0
      Value *CFValue = getRegOrArgValue(EFLAGS::CF, MBBNo);
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      assert((CFValue != nullptr) && (ZFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVA!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // CF or ZF
      BinaryOperator *CFZFOrCond =
          BinaryOperator::CreateOr(CFValue, ZFValue, "CFZFOR_CMOVA");
      RaisedBB->getInstList().push_back(CFZFOrCond);
      // Test CF == 0 and ZF == 0
      CMOVCond = new ICmpInst(Pred, CFZFOrCond, FalseValue, "Cond_CMOVA");
    } break;
    case X86::COND_L: {
      // Check SF != OF
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
      assert((SFValue != nullptr) && (OFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVL!");
      Pred = CmpInst::Predicate::ICMP_NE;
      // Test SF != OF
      CMOVCond = new ICmpInst(Pred, SFValue, OFValue, "Cond_CMOVL");
    } break;
    case X86::COND_G: {
      // Check ZF == 0 and SF == OF
      Value *ZFValue = getRegOrArgValue(EFLAGS::ZF, MBBNo);
      Value *SFValue = getRegOrArgValue(EFLAGS::SF, MBBNo);
      Value *OFValue = getRegOrArgValue(EFLAGS::OF, MBBNo);
      assert((ZFValue != nullptr) && (SFValue != nullptr) &&
             (OFValue != nullptr) &&
             "Failed to get EFLAGS value while raising CMOVG!");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare ZF and 0
      CmpInst *ZFCond = new ICmpInst(Pred, ZFValue, FalseValue, "ZFCmp_CMOVG");
      RaisedBB->getInstList().push_back(ZFCond);
      // Test SF == OF
      CmpInst *SFOFCond = new ICmpInst(Pred, SFValue, OFValue, "SFOFCmp_CMOVG");
      RaisedBB->getInstList().push_back(SFOFCond);
      CMOVCond = BinaryOperator::CreateAnd(ZFCond, SFOFCond, "Cond_CMOVG");
    } break;
    case X86::COND_INVALID:
      assert(false && "CMOV instruction with invalid condition found");
      break;
    default:
      assert(false && "CMOV instruction with unhandled condition found");
      break;
    }
    RaisedBB->getInstList().push_back(dyn_cast<Instruction>(CMOVCond));
    // Generate SelectInst for CMOV instruction
    SelectInst *SI = SelectInst::Create(CMOVCond, SrcValue, DstValue, "CMOV");
    RaisedBB->getInstList().push_back(SI);

    // Update the value mapping of DstPReg
    raisedValues->setPhysRegSSAValue(DstPReg, MBBNo, SI);
    Success = true;
  } break;
  default:
    assert(false && "Unhandled move reg-to-reg instruction");
    break;
  }
  return Success;
}

bool X86MachineInstructionRaiser::raiseLEAMachineInstr(const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();

  assert(MI.getNumExplicitOperands() == 6 &&
         "Unexpected number of arguments of lea instruction");
  // Get dest operand
  MachineOperand DestOp = MI.getOperand(0);
  assert(DestOp.isReg() &&
         "Unhandled non-register destination operand in lea instruction");
  unsigned int DestReg = DestOp.getReg();

  int OpIndex = X86II::getMemoryOperandNo(MI.getDesc().TSFlags);
  assert(OpIndex >= 0 && "Failed to get first operand of addressing-mode "
                         "expression in lea instruction");

  MachineOperand BaseRegOp = MI.getOperand(OpIndex + X86::AddrBaseReg);
  assert(BaseRegOp.isReg() &&
         "Unhandled non-register BaseReg operand in lea instruction");
  unsigned int BaseReg = BaseRegOp.getReg();
  Value *EffectiveAddrValue = nullptr;

  // If the basereg refers stack, get the stack allocated object value
  uint64_t BaseSupReg = find64BitSuperReg(BaseReg);
  if ((BaseSupReg == x86RegisterInfo->getStackRegister()) ||
      (BaseSupReg == x86RegisterInfo->getFramePtr())) {
    // Get index of memory reference in the instruction.
    int memoryRefOpIndex = getMemoryRefOpIndex(MI);
    // Should have found the index of the memory reference operand
    assert(memoryRefOpIndex != -1 && "Unable to find memory reference "
                                     "operand of a load/store instruction");
    X86AddressMode memRef = llvm::getAddressFromInstr(&MI, memoryRefOpIndex);
    EffectiveAddrValue = getStackAllocatedValue(MI, memRef, false);
  } else {
    MachineOperand ScaleAmtOp = MI.getOperand(OpIndex + X86::AddrScaleAmt);
    assert(ScaleAmtOp.isImm() &&
           "Unhandled non-immediate ScaleAmt operand in lea instruction");

    MachineOperand IndexRegOp = MI.getOperand(OpIndex + X86::AddrIndexReg);
    assert(IndexRegOp.isReg() &&
           "Unhandled non-register IndexReg operand in lea instruction");

    unsigned int IndexReg = IndexRegOp.getReg();

    MachineOperand SegmentRegOp = MI.getOperand(OpIndex + X86::AddrSegmentReg);
    assert(SegmentRegOp.getReg() == X86::NoRegister &&
           "Unhandled vaule of SegmentReg operand in lea instruction");

    MachineOperand Disp = MI.getOperand(OpIndex + X86::AddrDisp);
    assert(Disp.isImm() &&
           "Unhandled non-immediate Disp operand in lea instruction");

    // Check the sanity of register sizes
    if ((Opcode == X86::LEA64r) || (Opcode == X86::LEA64_32r)) {
      // lea64mem (see LEA64 and LEA64_32r description in
      // X86InstrArithmetic.td)
      assert((is64BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-64 bit base register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is64BitPhysReg(IndexReg)) &&
             "Unexpected index register type in lea instruction");
      assert(IndexReg != x86RegisterInfo->getStackRegister() &&
             "Unexpected stack pointer register as indexReg operand of lea "
             "instruction");
      if (Opcode == X86::LEA64_32r) {
        assert(is32BitPhysReg(DestReg) &&
               "Unexpected non-32 bit destination register in lea "
               "instruction");
      } else {
        assert(is64BitPhysReg(DestReg) &&
               "Unexpected non-32 bit dest register in lea instruction");
      }
    } else if (Opcode == X86::LEA32r) {
      assert((is32BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-32 bit base register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is32BitPhysReg(IndexReg)) &&
             "Unexpected indext register type in lea instruction");
      assert(is32BitPhysReg(DestReg) &&
             "Unexpected non-32 bit dest register in lea instruction");
    } else if (Opcode == X86::LEA16r) {
      assert((is16BitPhysReg(BaseReg) || BaseReg == X86::NoRegister) &&
             "Unexpected non-16 bit source register in lea instruction");
      assert(((IndexReg == X86::NoRegister) || is16BitPhysReg(IndexReg)) &&
             "Unexpected indext register type in lea instruction");
      assert(is16BitPhysReg(DestReg) &&
             "Unexpected non-16 bit dest register in lea instruction");
    }
    if (BaseReg == X86::RIP)
      EffectiveAddrValue = createPCRelativeAccesssValue(MI);
    else
      EffectiveAddrValue = getMemoryAddressExprValue(MI);
  }

  assert((EffectiveAddrValue != nullptr) &&
         "Failed to get effective address value");

  // Update the value mapping of DestReg
  raisedValues->setPhysRegSSAValue(DestReg, MI.getParent()->getNumber(),
                                   EffectiveAddrValue);
  return true;
}

bool X86MachineInstructionRaiser::raiseBinaryOpRegToRegMachineInstr(
    const MachineInstr &MI) {

  auto MCID = MI.getDesc();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Convenience variables for instructions with a dest and one or two
  // operands
  const unsigned DestOpIndex = 0, UseOp1Index = 1, UseOp2Index = 2;
  std::vector<Value *> Uses;
  int MBBNo = MI.getParent()->getNumber();

  for (const MachineOperand &MO : MI.explicit_uses()) {
    assert(MO.isReg() &&
           "Unexpected non-register operand in binary op instruction");
    unsigned int SrcReg = MO.getReg();
    Value *SrcValue = getRegOrArgValue(SrcReg, MBBNo);
    Uses.push_back(SrcValue);
  }
  // Verify there are exactly 2 use operands or source and dest operands are
  // the same i.e., source operand tied to dest operand.
  assert((Uses.size() == 2 ||
          ((Uses.size() == 1) &&
           (MI.findTiedOperandIdx(DestOpIndex) == UseOp1Index))) &&
         "Unexpected number of operands in register binary op instruction");

  // If the instruction has two use operands, ensure that their values are
  // of the same type and non-pointer type.
  if (Uses.size() == 2) {
    Value *Src1Value = Uses.at(0);
    Value *Src2Value = Uses.at(1);
    // The user operand values can be null if the instruction is 'xor op
    // op'. See below.
    if ((Src1Value != nullptr) && (Src2Value != nullptr)) {
      // If this is a pointer type, convert it to int type
      while (Src1Value->getType()->isPointerTy()) {
        PtrToIntInst *ConvPtrToInst = new PtrToIntInst(
            Src1Value, Src1Value->getType()->getPointerElementType());
        RaisedBB->getInstList().push_back(ConvPtrToInst);
        Src1Value = ConvPtrToInst;
      }

      // If this is a pointer type, convert it to int type
      while (Src2Value->getType()->isPointerTy()) {
        PtrToIntInst *ConvPtrToInst = new PtrToIntInst(
            Src2Value, Src2Value->getType()->getPointerElementType());
        RaisedBB->getInstList().push_back(ConvPtrToInst);
        Src2Value = ConvPtrToInst;
      }
      assert(Src1Value->getType()->isIntegerTy() &&
             Src2Value->getType()->isIntegerTy() &&
             "Unhandled operand value types in reg-to-reg binary op "
             "instruction");
      if (Src1Value->getType() != Src2Value->getType()) {
        // Cast the second operand to the type of second.
        // NOTE : The choice of target cast type is rather arbitrary. May
        // need a closer look.
        Type *DestValueTy = Src1Value->getType();
        Instruction *CInst = CastInst::Create(
            CastInst::getCastOpcode(Src2Value, false, DestValueTy, false),
            Src2Value, DestValueTy);
        RaisedBB->getInstList().push_back(CInst);
        Src2Value = CInst;
      }
      Uses[0] = Src1Value;
      Uses[1] = Src2Value;
    }
  }

  // Figure out the destination register, corresponding value and the
  // binary operator.
  unsigned int dstReg = X86::NoRegister;
  Value *dstValue = nullptr;
  unsigned opc = MI.getOpcode();
  // Construct the appropriate binary operation instruction
  switch (opc) {
  case X86::ADD8rr:
  case X86::ADD32rr:
  case X86::ADD64rr:
    // Verify the def operand is a register.
    assert(MI.getOperand(DestOpIndex).isReg() &&
           "Expecting destination of add instruction to be a register "
           "operand");
    assert((MCID.getNumDefs() == 1) &&
           "Unexpected number of defines in an add instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "add");
    dstReg = MI.getOperand(DestOpIndex).getReg();
    dstValue = BinaryOperator::CreateNSWAdd(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Set SF and ZF based on dstValue; technically OF, AF, CF and PF also needs
    // to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MBBNo, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, dstValue);

    // Update the value of dstReg
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
    break;
  case X86::IMUL32rr:
  case X86::IMUL64rr:
    // Verify the def operand is a register.
    assert(MI.getOperand(DestOpIndex).isReg() &&
           "Expecting destination of mul instruction to be a register "
           "operand");
    assert((MCID.getNumDefs() == 1) &&
           "Unexpected number of defines in a mul instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "mul");
    dstReg = MI.getOperand(DestOpIndex).getReg();
    dstValue = BinaryOperator::CreateNSWMul(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Setting EFLAG bits does not seem to matter, so not setting
    // Set the dstReg value
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
    break;

  case X86::AND8rr:
  case X86::AND16rr:
  case X86::AND32rr:
  case X86::AND64rr:
  case X86::OR32rr:
  case X86::OR64rr:
  case X86::XOR32rr:
  case X86::XOR64rr: {
    // Verify the def operand is a register.
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    const MachineOperand &Use2Op = MI.getOperand(UseOp2Index);
    assert(DestOp.isReg() && "Expecting destination of xor instruction to "
                             "be a register operand");
    assert((MCID.getNumDefs() == 1) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a xor instruction");
    dstReg = DestOp.getReg();
    // Generate an or instruction to set the zero flag if the
    // operands are the same. An instruction such as 'xor $ecx, ecx' is
    // generated to set the register value to 0.
    if ((MI.findTiedOperandIdx(1) == 0) && (dstReg == Use2Op.getReg())) {
      // No instruction to generate. Just set destReg value to 0.
      Type *DestTy = getPhysRegOperandType(MI, 0);
      Value *Val = ConstantInt::get(DestTy, 0, false /* isSigned */);
      dstValue = Val;
      // Set SF and ZF knowing that the value is 0
      raisedValues->setEflagValue(EFLAGS::SF, MBBNo, false);
      raisedValues->setEflagValue(EFLAGS::ZF, MBBNo, true);
    } else {
      assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
             "Unhandled situation: register used before initialization in "
             "xor");
      switch (opc) {
      case X86::AND8rr:
      case X86::AND16rr:
      case X86::AND32rr:
      case X86::AND64rr:
        dstValue = BinaryOperator::CreateAnd(Uses.at(0), Uses.at(1));
        break;
      case X86::OR32rr:
      case X86::OR64rr:
        dstValue = BinaryOperator::CreateOr(Uses.at(0), Uses.at(1));
        break;
      case X86::XOR32rr:
      case X86::XOR64rr:
        dstValue = BinaryOperator::CreateXor(Uses.at(0), Uses.at(1));
        break;
      default:
        assert(false && "Reached unexpected location");
      }
      if (isa<Instruction>(dstValue))
        RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
      // Set SF and ZF based on dstValue; technically PF also needs
      // to be set but ignoring for now.
      raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MBBNo, dstValue);
      raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, dstValue);
    }
    // Clear OF and CF
    raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
    raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
    // Update the value of dstReg
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  } break;
  case X86::TEST8rr:
  case X86::TEST16rr:
  case X86::TEST32rr:
  case X86::TEST64rr:
    assert((MCID.getNumDefs() == 0) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a test instruction");
    assert((Uses.at(0) != nullptr) && (Uses.at(1) != nullptr) &&
           "Unhandled situation: register is used before initialization in "
           "test");
    dstReg = X86::EFLAGS;
    dstValue = BinaryOperator::CreateAnd(Uses.at(0), Uses.at(1));
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Clear OF and CF
    raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
    raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
    // Set SF and ZF based on dstValue; technically PF also needs
    // to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MBBNo, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, dstValue);
    break;
  case X86::NEG8r:
  case X86::NEG16r:
  case X86::NEG32r:
  case X86::NEG64r: {
    // Verify source and dest are tied and are registers
    const MachineOperand &DestOp = MI.getOperand(DestOpIndex);
    assert(DestOp.isTied() &&
           (MI.findTiedOperandIdx(DestOpIndex) == UseOp1Index) &&
           "Expect tied operand in neg instruction");
    assert(DestOp.isReg() && "Expect reg operand in neg instruction");
    assert((MCID.getNumDefs() == 1) &&
           MCID.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
           "Unexpected defines in a neg instruction");
    dstReg = DestOp.getReg();
    Value *SrcOp = Uses.at(0);
    dstValue = BinaryOperator::CreateNeg(SrcOp);
    // Set CF to 0 if source operand is 0
    // Note: Add this instruction _before_ adding the result of neg
    raisedValues->testAndSetEflagSSAValue(EFLAGS::CF, MBBNo, SrcOp);
    // Now add the neg instruction
    if (isa<Instruction>(dstValue))
      RaisedBB->getInstList().push_back(dyn_cast<Instruction>(dstValue));
    // Now set up the flags according to the result
    // Set SF and ZF based on dstValue; technically PF also needs
    // to be set but ignoring for now.
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MBBNo, dstValue);
    raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, dstValue);

    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  } break;
  default:
    assert(false && "Unhandled binary instruction");
  }
  assert(dstValue != nullptr && (dstReg != X86::NoRegister) &&
         "Raising of instruction unimplemented");
  if (dstReg != X86::EFLAGS)
    // dstReg is set to X86::EFLAGS for TEST instruction which does not write to
    // any physical register
    raisedValues->setPhysRegSSAValue(dstReg, MBBNo, dstValue);
  return true;
}

bool X86MachineInstructionRaiser::raiseBinaryOpMemToRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {
  unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();

  assert((MIDesc.getNumDefs() == 1) &&
         "Encountered memory load instruction with more than 1 defs");
  unsigned int DestIndex = 0;
  const MachineOperand &DestOp = MI.getOperand(DestIndex);
  assert(DestOp.isReg() &&
         "Expect destination register operand in binary reg/mem instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  unsigned int DestPReg = DestOp.getReg();
  unsigned int MemAlignment = getInstructionMemOpSize(Opcode);
  Type *DestopTy = getPhysRegOperandType(MI, DestIndex);
  Value *DestValue = getRegOrArgValue(DestPReg, MI.getParent()->getNumber());
  assert(DestValue != nullptr &&
         "Encountered instruction with undefined register");

  // Verify sanity of the instruction.
  assert((DestValue->getType()->getPrimitiveSizeInBits() / sizeof(uint64_t)) ==
             MemAlignment &&
         "Mismatched value type size and instruction size of binary op "
         "instruction");
  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an LoadInst that loads an address in memory..
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in binary mem op instruction");
  bool IsMemRefGlobalVal = false;
  // If it is an effective address
  if (isEffectiveAddrValue(MemRefValue)) {
    // Check if this is a load if a global value
    if (isa<LoadInst>(MemRefValue)) {
      LoadInst *LdInst = dyn_cast<LoadInst>(MemRefValue);
      if (isa<GlobalValue>(LdInst->getPointerOperand())) {
        IsMemRefGlobalVal = true;
      }
    } else {
      // This is an effective address computation
      // Cast it to a pointer of type of destination operand.
      PointerType *PtrTy = PointerType::get(DestopTy, 0);
      IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(ConvIntToPtr);
      MemRefValue = ConvIntToPtr;
    }
  }
  Value *LoadValue = nullptr;
  if (IsMemRefGlobalVal) {
    // Load the global value.
    LoadInst *LdInst =
        new LoadInst(dyn_cast<LoadInst>(MemRefValue)->getPointerOperand());
    LdInst->setAlignment(MemAlignment);
    LoadValue = LdInst;
  } else {
    LoadInst *LdInst = new LoadInst(MemRefValue);
    LdInst->setAlignment(MemAlignment);
    LoadValue = LdInst;
  }
  // Insert the instruction that loads memory reference
  RaisedBB->getInstList().push_back(dyn_cast<Instruction>(LoadValue));
  Instruction *BinOpInst = nullptr;

  // Generate cast instruction to ensure source and destination types are
  // consistent, as needed.
  if (DestValue->getType() != LoadValue->getType()) {
    Type *DestValueTy = DestValue->getType();
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(LoadValue, false, DestValueTy, false),
        LoadValue, DestValueTy);
    RaisedBB->getInstList().push_back(CInst);
    LoadValue = CInst;
  }

  switch (Opcode) {
  case X86::ADD64rm:
  case X86::ADD32rm:
  case X86::ADD16rm:
  case X86::ADD8rm: {
    // Create add instruction
    BinOpInst = BinaryOperator::CreateAdd(DestValue, LoadValue);
  } break;
  case X86::OR32rm: {
    // Create add instruction
    BinOpInst = BinaryOperator::CreateOr(DestValue, LoadValue);
  } break;
  case X86::IMUL32rm: {
    // One-operand form of IMUL
    // Create mul instruction
    BinOpInst = BinaryOperator::CreateMul(DestValue, LoadValue);
  } break;
  case X86::IMUL16rmi:
  case X86::IMUL16rmi8:
  case X86::IMUL32rmi:
  case X86::IMUL32rmi8:
  case X86::IMUL64rmi8:
  case X86::IMUL64rmi32: {
    // Two-operand form of IMUL
    // Get index of memory reference in the instruction.
    int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
    // The index of the memory reference operand should be 1
    assert(MemoryRefOpIndex == 1 &&
           "Unexpected memory reference operand index in imul instruction");
    const MachineOperand &SecondSourceOp =
        MI.getOperand(MemoryRefOpIndex + X86::AddrNumOperands);
    // Second source should be an immediate.
    assert(SecondSourceOp.isImm() &&
           "Expect immediate operand in imul instruction");
    // Construct the value corresponding to immediate operand
    Value *SecondSourceVal =
        ConstantInt::get(LoadValue->getType(), SecondSourceOp.getImm());
    // Create mul instruction
    BinOpInst = BinaryOperator::CreateMul(SecondSourceVal, LoadValue);
  } break;
  default:
    assert(false && "Unhandled binary op mem to reg instruction ");
  }
  // Add instruction to block
  RaisedBB->getInstList().push_back(BinOpInst);

  // Update PhysReg to Value map
  raisedValues->setPhysRegSSAValue(DestPReg, MI.getParent()->getNumber(),
                                   BinOpInst);
  return true;
}

bool X86MachineInstructionRaiser::raiseLoadIntToFloatRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {

  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 0 && "Expect memory operand of floating-point "
                                  "load instruction at index 0");
  assert(MIDesc.getNumDefs() == 0 &&
         "Expect no defs in floating-point load instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in FPU load op instruction");

  LLVMContext &llvmContext(MF.getFunction().getContext());
  if (IsPCRelMemRef) {
    // If it is a PC-relative mem ref, memRefValue is a
    // global value loaded from PC-relative memory location. If it is a
    // derived type value, get its element pointer.
    Type *MemRefValueTy = MemRefValue->getType();
    if (!MemRefValueTy->isFloatingPointTy()) {
      assert(MemRefValueTy->isPointerTy() &&
             "Unhandled non-pointer type found while attempting to push value "
             "to FPU register stack.");
      Type *MemRefValPtrElementTy = MemRefValueTy->getPointerElementType();
      switch (MemRefValPtrElementTy->getTypeID()) {
      case Type::ArrayTyID: {
        assert(MemRefValPtrElementTy->getArrayNumElements() == 1 &&
               "Unexpected number of array elements in value being cast to "
               "float");
        // Make sure the array element type is integer or floating point
        // type.
        Type *ArrElemTy = MemRefValPtrElementTy->getArrayElementType();
        assert((ArrElemTy->isIntegerTy() || ArrElemTy->isFloatingPointTy()) &&
               "Unexpected type of data referenced in FPU register stack "
               "load instruction");
        // Get the element
        Value *IndexOne = ConstantInt::get(llvmContext, APInt(32, 1));
        Instruction *GetElem = GetElementPtrInst::CreateInBounds(
            MemRefValPtrElementTy, MemRefValue, {IndexOne, IndexOne}, "",
            RaisedBB);
        MemRefValue = GetElem;
      } break;
      // Primitive types that need not be reached into.
      case Type::IntegerTyID:
        break;
      default: {
        assert(false && "Encountered value with type whose cast to float is "
                        "not yet handled");
      } break;
      }
    }
  }
  // If it is an effective address value, convert it to a pointer to
  // the type of load reg.
  if (isEffectiveAddrValue(MemRefValue)) {
    assert(false &&
           "*** Unhandled situation. Need to implement support correctly");
    Type *PtrTy = MemRefValue->getType();
    IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
    RaisedBB->getInstList().push_back(ConvIntToPtr);
    MemRefValue = ConvIntToPtr;
  }
  assert(MemRefValue->getType()->isPointerTy() &&
         "Pointer type expected in load instruction");
  // Load the value from memory location
  LoadInst *LdInst = new LoadInst(MemRefValue);
  unsigned int MemAlignment = MemRefValue->getType()
                                  ->getPointerElementType()
                                  ->getPrimitiveSizeInBits() /
                              8;
  LdInst->setAlignment(MemAlignment);
  RaisedBB->getInstList().push_back(LdInst);

  switch (Opcode) {
  default: {
    assert(false && "Unhandled load floating-point register instruction");
  } break;
  case X86::ILD_F32m:
  case X86::ILD_F64m: {
    Type *FloatTy = Type::getFloatTy(llvmContext);
    assert(LdInst->getType()->isIntegerTy() &&
           "Unexpected non-integter type of source in fild instruction");
    // Cast source to float
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(LdInst, true, FloatTy, true), LdInst, FloatTy);
    RaisedBB->getInstList().push_back(CInst);
    // Push value to top of FPU register stack
    FPURegisterStackPush(CInst);
  } break;
  case X86::LD_F32m: {
    Type *FloatTy = Type::getFloatTy(llvmContext);
    // Cast source to float
    Instruction *CInst = CastInst::Create(
        CastInst::getCastOpcode(LdInst, true, FloatTy, true), LdInst, FloatTy);
    RaisedBB->getInstList().push_back(CInst);
    // Push value to top of FPU register stack
    FPURegisterStackPush(CInst);
  }
  }
  return true;
}

bool X86MachineInstructionRaiser::raiseStoreIntToFloatRegInstr(
    const MachineInstr &MI, Value *MemRefValue) {

  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 0 && "Expect memory operand of floating-point "
                                  "load instruction at index 0");
  assert(MIDesc.getNumDefs() == 0 &&
         "Expect no defs in floating-point load instruction");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue)) &&
         "Unexpected type of memory reference in FPU store op instruction");

  LLVMContext &llvmContext(MF.getFunction().getContext());
  if (IsPCRelMemRef) {
    // If it is a PC-relative mem ref, memRefValue is a global value loaded
    // from PC-relative memory location. If it is a derived type value, get
    // its element pointer.
    Type *MemRefValueTy = MemRefValue->getType();
    if (!MemRefValueTy->isFloatingPointTy()) {
      assert(MemRefValueTy->isPointerTy() &&
             "Unhandled non-pointer type found while attempting to load value "
             "from FPU register stack.");
      Type *MemRefValPtrElementTy = MemRefValueTy->getPointerElementType();
      switch (MemRefValPtrElementTy->getTypeID()) {
      case Type::ArrayTyID: {
        assert(MemRefValPtrElementTy->getArrayNumElements() == 1 &&
               "Unexpected number of array elements in value being cast to "
               "float");
        // Make sure the array element type is integer or floating point
        // type.
        Type *ArrElemTy = MemRefValPtrElementTy->getArrayElementType();
        assert((ArrElemTy->isIntegerTy() || ArrElemTy->isFloatingPointTy()) &&
               "Unexpected type of data referenced in FPU register stack "
               "store instruction");
        // Get the element
        Value *IndexOne = ConstantInt::get(llvmContext, APInt(32, 1));
        Instruction *GetElem = GetElementPtrInst::CreateInBounds(
            MemRefValPtrElementTy, MemRefValue, {IndexOne, IndexOne}, "",
            RaisedBB);
        MemRefValue = GetElem;
      } break;
      // Primitive types that need not be reached into.
      case Type::IntegerTyID:
        break;
      default: {
        assert(false && "Encountered value with type whose cast to float is "
                        "not yet handled");
      } break;
      }
    }
  }
  // If it is an effective address value, convert it to a pointer to
  // the type of load reg.
  if (isEffectiveAddrValue(MemRefValue)) {
    assert(false &&
           "*** Unhandled situation. Need to implement support correctly");
    Type *PtrTy = MemRefValue->getType();
    IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
    RaisedBB->getInstList().push_back(ConvIntToPtr);
    MemRefValue = ConvIntToPtr;
  }
  assert(MemRefValue->getType()->isPointerTy() &&
         "Pointer type expected in store instruction");

  switch (Opcode) {
  default: {
    assert(false && "Unhandled store floating-point register instruction");
  } break;
  case X86::ST_FP32m:
  case X86::ST_FP64m: {
    Value *ST0Val = FPURegisterStackTop();
    Type *SrcTy = ST0Val->getType();
    // The value in ST0 is converted to single-precision or double precision
    // floating-point format. So, cast the memRefValue to the PointerType of
    // SrcTy.
    Type *DestElemTy = MemRefValue->getType()->getPointerElementType();
    if (DestElemTy != SrcTy) {
      PointerType *SrcPtrTy = SrcTy->getPointerTo(0);
      Instruction *CInst = CastInst::Create(
          CastInst::getCastOpcode(MemRefValue, true, SrcPtrTy, true),
          MemRefValue, SrcPtrTy);
      RaisedBB->getInstList().push_back(CInst);
      MemRefValue = CInst;
    }
    // Create the store
    StoreInst *StInst = new StoreInst(ST0Val, MemRefValue);
    RaisedBB->getInstList().push_back(StInst);

    // Pop value to top of FPU register stack
    FPURegisterStackPop();
  }
  }
  return true;
}

bool X86MachineInstructionRaiser::raiseMoveFromMemInstr(const MachineInstr &MI,
                                                        Value *MemRefValue) {
  const unsigned int Opcode = MI.getOpcode();
  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned LoadOpIndex = 0;
  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  assert(MemoryRefOpIndex == 1 &&
         "Expect memory operand of a mem move instruction at index 1");
  assert(MIDesc.getNumDefs() == 1 && MI.getOperand(LoadOpIndex).isReg() &&
         "Expect store operand register target");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);
  uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
  bool IsPCRelMemRef = (BaseSupReg == X86::RIP);
  const MachineOperand &LoadOp = MI.getOperand(LoadOpIndex);
  unsigned int LoadPReg = LoadOp.getReg();
  assert(TargetRegisterInfo::isPhysicalRegister(LoadPReg) &&
         "Expect destination to be a physical register in move from mem "
         "instruction");

  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefValue) || isEffectiveAddrValue(MemRefValue) ||
          isa<GlobalValue>(MemRefValue) ||
          isa<GetElementPtrInst>(MemRefValue)) &&
         "Unexpected type of memory reference in binary mem op instruction");

  if (IsPCRelMemRef && !isa<GetElementPtrInst>(MemRefValue)) {
    // memRefValue already represents the global value loaded from
    // PC-relative memory location. It is incorrect to generate an
    // additional load of this value. It should be directly used.
    raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                     MemRefValue);
  } else {
    // If it is an effective address value, convert it to a pointer to the
    // type of load reg.
    if (isEffectiveAddrValue(MemRefValue)) {
      PointerType *PtrTy =
          PointerType::get(getPhysRegOperandType(MI, LoadOpIndex), 0);
      IntToPtrInst *ConvIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(ConvIntToPtr);
      MemRefValue = ConvIntToPtr;
    }
    assert(MemRefValue->getType()->isPointerTy() &&
           "Pointer type expected in load instruction");
    // Load the value from memory location
    LoadInst *LdInst = new LoadInst(MemRefValue);
    unsigned int MemAlignment = MemRefValue->getType()
                                    ->getPointerElementType()
                                    ->getPrimitiveSizeInBits() /
                                8;
    LdInst->setAlignment(MemAlignment);
    RaisedBB->getInstList().push_back(LdInst);

    LLVMContext &Ctx(MF.getFunction().getContext());
    Type *MemTy = nullptr;
    Type *ExtTy = nullptr;
    switch (Opcode) {
    default: {
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       LdInst);
    } break;
    case X86::MOVSX64rm32: {
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt32Ty(Ctx);
    } break;
    case X86::MOVZX64rm16: {
    case X86::MOVSX64rm16:
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
    } break;
    case X86::MOVZX64rm8:
    case X86::MOVSX64rm8: {
      ExtTy = Type::getInt64Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
    } break;

    case X86::MOVZX32rm8:
    case X86::MOVZX32rm8_NOREX:
    case X86::MOVSX32rm8: {
      ExtTy = Type::getInt32Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
    } break;
    case X86::MOVZX32rm16:
    case X86::MOVSX32rm16: {
      ExtTy = Type::getInt32Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
    } break;

    case X86::MOVZX16rm8:
    case X86::MOVSX16rm8: {
      ExtTy = Type::getInt16Ty(Ctx);
      MemTy = Type::getInt8Ty(Ctx);
    } break;
    case X86::MOVZX16rm16:
    case X86::MOVSX16rm16: {
      ExtTy = Type::getInt16Ty(Ctx);
      MemTy = Type::getInt16Ty(Ctx);
    } break;
    }
    // Decide based on opcode value and not opcode name??
    bool IsSextInst =
        x86InstrInfo->getName(MIDesc.getOpcode()).startswith("MOVSX");
    bool IsZextInst =
        x86InstrInfo->getName(MIDesc.getOpcode()).startswith("MOVZX");

    if (IsSextInst || IsZextInst) {
      assert(((ExtTy != nullptr) && (MemTy != nullptr)) &&
             "Unhandled move from memory instruction");

      // Load value of type memTy
      Instruction *CInst = LdInst;
      if (LdInst->getType() != MemTy) {
        CInst = CastInst::Create(
            CastInst::getCastOpcode(LdInst, false, MemTy, false), LdInst,
            MemTy);
        RaisedBB->getInstList().push_back(CInst);
      }
      Instruction *ExtInst;

      // Now extend the value accordingly
      if (IsSextInst) {
        // Sign extend
        ExtInst = new SExtInst(CInst, ExtTy);
      } else {
        // Zero extend
        ExtInst = new ZExtInst(CInst, ExtTy);
      }
      RaisedBB->getInstList().push_back(ExtInst);
      // Update PhysReg to Value map
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       ExtInst);
    } else {
      // This is a normal mov instruction
      // Update PhysReg to Value map
      raisedValues->setPhysRegSSAValue(LoadPReg, MI.getParent()->getNumber(),
                                       LdInst);
    }
  }

  return true;
}

bool X86MachineInstructionRaiser::raiseMoveToMemInstr(const MachineInstr &MI,
                                                      Value *MemRefVal) {
  unsigned int SrcOpIndex = getMemoryRefOpIndex(MI) + X86::AddrNumOperands;

  const MachineOperand &SrcOp = MI.getOperand(SrcOpIndex);

  assert((SrcOp.isImm() || SrcOp.isReg()) &&
         "Register or immediate value source expected in a move to mem "
         "instruction");
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  unsigned int memAlignment = getInstructionMemOpSize(MI.getOpcode());
  Value *SrcValue = nullptr;
  Type *SrcOpTy = nullptr;

  // If Source op is immediate, create a constant int value
  // of type memory location.
  if (SrcOp.isImm()) {
    SrcOpTy = getImmOperandType(MI, SrcOpIndex);
    SrcValue = ConstantInt::get(SrcOpTy, SrcOp.getImm());
  } else {
    // If it is not an immediate value, get source value
    SrcValue = getRegOperandValue(MI, SrcOpIndex);
    SrcOpTy = getPhysRegOperandType(MI, SrcOpIndex);
  }
  assert(SrcValue != nullptr &&
         "Unable to get source value while raising move to mem instruction");
  // Load the value from memory location of memRefValue.
  // memRefVal is either an AllocaInst (stack access) or GlobalValue (global
  // data access) or an effective address value.
  assert((isa<AllocaInst>(MemRefVal) || isEffectiveAddrValue(MemRefVal) ||
          isa<GlobalValue>(MemRefVal) || isa<GetElementPtrInst>(MemRefVal)) &&
         "Unexpected type of memory reference in mem-to-reg instruction");
  bool loadEffAddr = isEffectiveAddrValue(MemRefVal);

  // If memory reference is not a pointer type, cast it to a pointer
  Type *DstMemTy = MemRefVal->getType();
  if (!DstMemTy->isPointerTy()) {
    // Cast it as pointer to SrcOpTy
    PointerType *PtrTy = PointerType::get(SrcOpTy, 0);
    IntToPtrInst *convIntToPtr = new IntToPtrInst(MemRefVal, PtrTy);
    RaisedBB->getInstList().push_back(convIntToPtr);
    MemRefVal = convIntToPtr;
  }

  if (loadEffAddr) {
    // Load the value from memory location
    LoadInst *loadInst = new LoadInst(MemRefVal);
    loadInst->setAlignment(
        MemRefVal->getPointerAlignment(MR->getModule()->getDataLayout()));
    RaisedBB->getInstList().push_back(loadInst);
  }

  // This instruction moves a source value to memory. So, if the types of
  // the source value and that of the memory pointer content are not the
  // same, it is the source value that needs to be cast to match the type of
  // destination (i.e., memory). It needs to be sign extended as needed.
  Type *MatchTy = MemRefVal->getType()->getPointerElementType();
  if (!MatchTy->isArrayTy()) {
    if (SrcValue->getType() != MatchTy) {
      Type *CastTy = MatchTy;
      CastInst *CInst = CastInst::Create(
          CastInst::getCastOpcode(SrcValue, false, CastTy, false), SrcValue,
          CastTy);
      RaisedBB->getInstList().push_back(CInst);
      SrcValue = CInst;
    }
  }

  StoreInst *storeInst = new StoreInst(SrcValue, MemRefVal);

  storeInst->setAlignment(memAlignment);
  RaisedBB->getInstList().push_back(storeInst);
  return true;
}

// Raise idiv instruction with source operand with value srcValue.
bool X86MachineInstructionRaiser::raiseDivideInstr(const MachineInstr &MI,
                                                   Value *SrcValue) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  LLVMContext &Ctx(MF.getFunction().getContext());

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // idiv uses AX(AH:AL or DX:AX or EDX:EAX or RDX:RAX pairs as dividend and
  // stores the result in the same pair. Additionally, EFLAGS is an implicit
  // def.
  assert(MIDesc.getNumImplicitUses() == 2 && MIDesc.getNumImplicitDefs() == 3 &&
         MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
         "Unexpected number of implicit uses and defs in div instruction");
  MCPhysReg UseDefReg_0 = MIDesc.ImplicitUses[0];
  MCPhysReg UseDefReg_1 = MIDesc.ImplicitUses[1];
  assert((UseDefReg_0 == MIDesc.ImplicitDefs[0]) &&
         (UseDefReg_1 == MIDesc.ImplicitDefs[1]) &&
         "Unexpected use/def registers in div instruction");

  Value *DividendLowBytes =
      getRegOrArgValue(UseDefReg_0, MI.getParent()->getNumber());
  Value *DividendHighBytes =
      getRegOrArgValue(UseDefReg_1, MI.getParent()->getNumber());
  assert((DividendLowBytes != nullptr) && (DividendHighBytes != nullptr) &&
         "Unexpected use before definition in div instruction");
  // Divisor is srcValue.
  // Create a Value representing the dividend.
  // TODO: Not sure how the implicit use registers of IDIV8m are encode.
  // Does the instruction have AX as a single use/def register or does it
  // have 2 use/def registers, viz., AH:AL pair similar to the other IDIV
  // instructions? Handle it when it is encountered.
  assert((DividendLowBytes->getType() == DividendHighBytes->getType()) &&
         "Unexpected types of dividend registers in idiv instruction");
  unsigned int UseDefRegSize =
      DividendLowBytes->getType()->getScalarSizeInBits();
  // Generate the following code
  // %h = lshl DividendHighBytes, UseDefRegSize
  // %f = or %h, DividendLowBytes
  // %quo = idiv %f, srcValue
  // %rem = irem %f, srcValue
  // UseDef_0 = %quo
  // UseDef_1 = %rem

  // Logical Shift left DividendHighBytes by n-bits (where n is the size of
  // UseDefRegSize) to get the high bytes and set DefReg_1 to the resulting
  // value.
  // DoubleTy type is of type twice the use reg size
  Type *DoubleTy = Type::getIntNTy(Ctx, UseDefRegSize * 2);
  Value *ShiftAmountVal =
      ConstantInt::get(DoubleTy, UseDefRegSize, false /* isSigned */);
  // Cast DividendHighBytes and DividendLowBytes to types with double the
  // size.
  CastInst *DividendLowBytesDT = CastInst::Create(
      CastInst::getCastOpcode(DividendLowBytes, true, DoubleTy, true),
      DividendLowBytes, DoubleTy);
  RaisedBB->getInstList().push_back(DividendLowBytesDT);

  CastInst *DividendHighBytesDT = CastInst::Create(
      CastInst::getCastOpcode(DividendHighBytes, true, DoubleTy, true),
      DividendHighBytes, DoubleTy);
  RaisedBB->getInstList().push_back(DividendHighBytesDT);

  Instruction *LShlInst =
      BinaryOperator::CreateNUWShl(DividendHighBytesDT, ShiftAmountVal);
  RaisedBB->getInstList().push_back(LShlInst);

  // Combine the dividend values to get full dividend.
  // or instruction
  Instruction *FullDividend =
      BinaryOperator::CreateOr(LShlInst, DividendLowBytesDT);
  RaisedBB->getInstList().push_back(FullDividend);

  // If the srcValue is a stack allocation, load the value from the stack
  // slot
  if (isa<AllocaInst>(SrcValue)) {
    // Load the value from memory location
    LoadInst *loadInst = new LoadInst(SrcValue);
    unsigned int memAlignment =
        SrcValue->getType()->getPointerElementType()->getPrimitiveSizeInBits() /
        8;
    loadInst->setAlignment(memAlignment);
    RaisedBB->getInstList().push_back(loadInst);
    SrcValue = loadInst;
  }
  // Cast divisor (srcValue) to double type
  CastInst *srcValueDT =
      CastInst::Create(CastInst::getCastOpcode(SrcValue, true, DoubleTy, true),
                       SrcValue, DoubleTy);
  RaisedBB->getInstList().push_back(srcValueDT);

  // quotient
  Instruction *QuotientDT =
      BinaryOperator::CreateSDiv(FullDividend, srcValueDT);
  RaisedBB->getInstList().push_back(QuotientDT);

  // Cast Quotient back to UseDef reg value type
  CastInst *Quotient =
      CastInst::Create(CastInst::getCastOpcode(
                           QuotientDT, true, DividendLowBytes->getType(), true),
                       QuotientDT, DividendLowBytes->getType());

  RaisedBB->getInstList().push_back(Quotient);
  // Update ssa val of UseDefReg_0
  raisedValues->setPhysRegSSAValue(UseDefReg_0, MI.getParent()->getNumber(),
                                   Quotient);

  // remainder
  Instruction *RemainderDT =
      BinaryOperator::CreateSRem(FullDividend, srcValueDT);
  RaisedBB->getInstList().push_back(RemainderDT);

  // Cast RemainderDT back to UseDef reg value type
  CastInst *Remainder = CastInst::Create(
      CastInst::getCastOpcode(RemainderDT, true, DividendHighBytes->getType(),
                              true),
      RemainderDT, DividendHighBytes->getType());

  RaisedBB->getInstList().push_back(Remainder);
  // Update ssa val of UseDefReg_1
  raisedValues->setPhysRegSSAValue(UseDefReg_1, MI.getParent()->getNumber(),
                                   Remainder);

  return true;
}

// Raise compare instruction. If the the instruction is a memory compare, it
// is expected that this function is called from raiseMemRefMachineInstr
// after verifying the accessibility of memory location and with
// isMemCompare set true.If isMemCompare is true, memRefValue needs to be
// the non-null memory reference value representing the memory reference the
// instruction uses.

bool X86MachineInstructionRaiser::raiseCompareMachineInstr(
    const MachineInstr &MI, bool isMemCompare, Value *MemRefValue) {
  // Get index of memory reference in the instruction.
  int memoryRefOpIndex = getMemoryRefOpIndex(MI);
  int MBBNo = MI.getParent()->getNumber();
  assert((((memoryRefOpIndex != -1) && isMemCompare) ||
          ((memoryRefOpIndex == -1) && !isMemCompare)) &&
         "Inconsistent memory reference operand information specified for "
         "compare instruction");
  MCInstrDesc MCIDesc = MI.getDesc();
  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Is this a sub instruction?
  bool isSUBInst = x86InstrInfo->getName(MCIDesc.getOpcode()).startswith("SUB");

  SmallVector<Value *, 2> OpValues = {nullptr, nullptr};

  // Get operand indices
  if (isMemCompare) {
    // This is a memory referencing instruction.
    Type *NonMemRefOpTy;
    const MachineOperand *NonMemRefOp;
    assert(memoryRefOpIndex >= 0 &&
           "Unexpected memory operand index in compare instruction");
    unsigned nonMemRefOpIndex =
        (memoryRefOpIndex == 0) ? X86::AddrNumOperands : 0;
    NonMemRefOp = &(MI.getOperand(nonMemRefOpIndex));
    if (NonMemRefOp->isReg()) {
      NonMemRefOpTy = getPhysRegOperandType(MI, nonMemRefOpIndex);
    } else if (NonMemRefOp->isImm()) {
      NonMemRefOpTy = getImmOperandType(MI, nonMemRefOpIndex);
    } else {
      MI.dump();
      assert(false && "Unhandled second operand type in compare instruction");
    }

    assert(MemRefValue != nullptr && "Null memory reference value encountered "
                                     "while raising compare instruction");
    // Convert it to a pointer of type of non-memory operand
    if (isEffectiveAddrValue(MemRefValue)) {
      PointerType *PtrTy = PointerType::get(NonMemRefOpTy, 0);
      IntToPtrInst *convIntToPtr = new IntToPtrInst(MemRefValue, PtrTy);
      RaisedBB->getInstList().push_back(convIntToPtr);
      MemRefValue = convIntToPtr;
    }
    // Load the value from memory location
    LoadInst *loadInst = new LoadInst(MemRefValue);
    loadInst->setAlignment(
        MemRefValue->getPointerAlignment(MR->getModule()->getDataLayout()));
    RaisedBB->getInstList().push_back(loadInst);
    // save it at the appropriate index of operand value array
    if (memoryRefOpIndex == 0) {
      OpValues[0] = loadInst;
    } else {
      OpValues[1] = loadInst;
    }

    // Get value for non-memory operand of compare.
    Value *NonMemRefVal = nullptr;
    if (NonMemRefOp->isReg()) {
      NonMemRefVal =
          getRegOrArgValue(NonMemRefOp->getReg(), MI.getParent()->getNumber());
    } else if (NonMemRefOp->isImm()) {
      NonMemRefVal =
          ConstantInt::get(MemRefValue->getType()->getPointerElementType(),
                           NonMemRefOp->getImm());
    } else {
      MI.dump();
      assert(false && "Unhandled first operand type in compare instruction");
    }
    // save non-memory reference value at the appropriate index of operand
    // value array
    if (memoryRefOpIndex == 0) {
      OpValues[1] = NonMemRefVal;
    } else {
      OpValues[0] = NonMemRefVal;
    }
  } else {
    // The instruction operands do not reference memory
    unsigned Op1Index = MCIDesc.getNumDefs() == 0 ? 0 : 1;

    MachineOperand CmpOp1 = MI.getOperand(Op1Index);
    MachineOperand CmpOp2 = MI.getOperand(Op1Index + 1);

    assert((CmpOp1.isReg() || CmpOp1.isImm()) &&
           "Unhandled first operand type in compare instruction");

    assert((CmpOp2.isReg() || CmpOp2.isImm()) &&
           "Unhandled second operand type in compare instruction");

    if (CmpOp1.isReg()) {
      OpValues[0] =
          getRegOrArgValue(CmpOp1.getReg(), MI.getParent()->getNumber());
    }

    if (CmpOp2.isReg()) {
      OpValues[1] =
          getRegOrArgValue(CmpOp2.getReg(), MI.getParent()->getNumber());
    }

    // Construct value if either of the operands is an immediate
    if (CmpOp1.isImm()) {
      assert((OpValues[1] != nullptr) &&
             "At least one value expected while raising compare instruction");
      OpValues[0] = ConstantInt::get(OpValues[1]->getType(), CmpOp1.getImm());
    }

    if (CmpOp2.isImm()) {
      assert((OpValues[0] != nullptr) &&
             "At least one value expected while raising compare instruction");
      OpValues[1] = ConstantInt::get(OpValues[0]->getType(), CmpOp2.getImm());
    }
  }
  assert(OpValues[0] != nullptr && OpValues[1] != nullptr &&
         "Unable to materialize compare operand values");

  assert(MI.getOperand(0).isReg() && "Unexpected non-register def operand");
  // Make sure the source operand value types are the same as destination
  // register type.
  unsigned int DestReg = MI.getOperand(0).getReg();
  if (DestReg != X86::NoRegister) {
    Type *DestTy = getPhysRegOperandType(MI, 0);
    for (int i = 0; i < 2; i++) {
      if (OpValues[i]->getType() != DestTy) {
        CastInst *CInst = CastInst::Create(
            CastInst::getCastOpcode(OpValues[i], false, DestTy, false),
            OpValues[i], DestTy);
        RaisedBB->getInstList().push_back(CInst);
        OpValues[i] = CInst;
      }
    }
  } else {
    assert(OpValues[0]->getType() == OpValues[1]->getType() &&
           "Mis-matched operand types encountered while raising compare "
           "instruction");
  }
  raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
  raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
  Instruction *SubInst = BinaryOperator::CreateSub(OpValues[0], OpValues[1]);
  RaisedBB->getInstList().push_back(SubInst);

  if (isSUBInst) {
    switch (MI.getOpcode()) {
    case X86::SUB8mi:
    case X86::SUB8mr:
    case X86::SUB8rm:
    case X86::SUB16mi:
    case X86::SUB16mr:
    case X86::SUB16rm:
    case X86::SUB32mi:
    case X86::SUB32mr:
    case X86::SUB32rm:
    case X86::SUB64mi8:
    case X86::SUB64mi32:
    case X86::SUB64mr:
    case X86::SUB64rm:
    case X86::SUB32rr:
    case X86::SUB64rr: {
      assert(MCIDesc.getNumDefs() == 1 &&
             "Unexpected number of def operands of sub instruction");
      // Update the DestReg only if this is a sub instruction. Do not update if
      // this is a cmp instruction
      raisedValues->setPhysRegSSAValue(DestReg, MI.getParent()->getNumber(),
                                       SubInst);
    } break;
    default:
      assert(false && "Unhandled sub instruction found");
    }
  }
  // Now update EFLAGS
  assert(MCIDesc.getNumImplicitDefs() == 1 &&
         "Compare instruction does not have exactly one implicit def");
  MCPhysReg ImpDefReg = MCIDesc.ImplicitDefs[0];
  assert(ImpDefReg == X86::EFLAGS &&
         "Expected implicit EFLAGS def in compare instruction");
  // Create instructions to set CF and ZF flags according to the result
  // SubInst.
  raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MI.getParent()->getNumber(),
                                        SubInst);
  raisedValues->testAndSetEflagSSAValue(EFLAGS::SF, MI.getParent()->getNumber(),
                                        SubInst);
  return true;
}

// Raise a load/store instruction.
// Current implementation only raises instructions that load and store to
// stack.
bool X86MachineInstructionRaiser::raiseMemRefMachineInstr(
    const MachineInstr &MI) {

  // Handle the push instruction that is marked as a memory store
  // instruction
  if (isPushToStack(MI)) {
    return raisePushInstruction(MI);
  }

  if (isPopFromStack(MI)) {
    return raisePopInstruction(MI);
  }

  const MCInstrDesc &MIDesc = MI.getDesc();
  unsigned int Opcode = MI.getOpcode();

  int LoadOrStoreOpIndex = -1;

  // Get index of memory reference in the instruction.
  int MemoryRefOpIndex = getMemoryRefOpIndex(MI);
  // Should have found the index of the memory reference operand
  assert(MemoryRefOpIndex != -1 && "Unable to find memory reference "
                                   "operand of a load/store instruction");
  X86AddressMode MemRef = llvm::getAddressFromInstr(&MI, MemoryRefOpIndex);

  // Get the operand whose value is stored to memory or that is loaded from
  // memory.

  if (MIDesc.mayStore()) {
    // If the instruction stores to stack, find the register whose value is
    // being stored. It would be the operand at offset
    // memRefOperandStartIndex
    // + X86::AddrNumOperands
    LoadOrStoreOpIndex = MemoryRefOpIndex + X86::AddrNumOperands;
  } else if (MIDesc.mayLoad()) {
    // If the instruction loads to memory to a register, it has 1 def.
    // Operand 0 is the loadOrStoreOp.
    assert(((MIDesc.getNumDefs() == 0) || (MIDesc.getNumDefs() == 1)) &&
           "Instruction that loads from memory expected to have only "
           "one target");
    if (MIDesc.getNumDefs() == 1) {
      LoadOrStoreOpIndex = 0;
      assert(MI.getOperand(LoadOrStoreOpIndex).isReg() &&
             "Target of instruction that loads from "
             "memory expected to be a register");
    } else if (!MIDesc.isCompare()) {
      switch (getInstructionKind(Opcode)) {
      case InstructionKind::DIVIDE_MEM_OP:
      case InstructionKind::LOAD_FPU_REG:
        break;
      default:
        MI.print(errs());
        assert(false && "Encountered unhandled memory load instruction");
      }
    }
  } else {
    MI.print(errs());
    assert(false && "Encountered unhandled instruction that is not load/store");
  }

  Value *MemoryRefValue = nullptr;

  if (MemRef.BaseType == X86AddressMode::RegBase) {
    // If it is a stack reference, allocate a stack slot in case the current
    // memory reference is new. Else get the stack reference using the
    // stackslot index of the previously known stack ref.

    uint64_t BaseSupReg = find64BitSuperReg(MemRef.Base.Reg);
    if (BaseSupReg == x86RegisterInfo->getStackRegister() ||
        BaseSupReg == x86RegisterInfo->getFramePtr()) {
      MemoryRefValue = getStackAllocatedValue(MI, MemRef, false);
    }
    // Handle PC-relative addressing.

    // NOTE: This tool now raises only shared libraries and executables -
    // NOT object files. So, instructions with 0 register (which typically
    // are seen in a relocatable object file for the linker to patch) are
    // not expected to be encountered.
    else if (BaseSupReg == X86::RIP) {
      MemoryRefValue = createPCRelativeAccesssValue(MI);
    } else {
      // Get load/store operand
      Value *memrefValue = getMemoryAddressExprValue(MI);
      MemoryRefValue = memrefValue;
    }
  } else {
    // TODO : Memory references with BaseType FrameIndexBase
    // (i.e., not RegBase type)
    outs() << "****** Unhandled memory reference in instruction\n\t";
    MI.dump();
    outs() << "****** reference of type FrameIndexBase";
    return false;
  }

  assert(MemoryRefValue != nullptr &&
         "Unable to construct memory referencing value");

  // Raise a memory compare instruction
  if (MI.isCompare()) {
    return raiseCompareMachineInstr(MI, true /* isMemRef */, MemoryRefValue);
  }

  // Now that we have all necessary information about memory reference and
  // the load/store operand, we can raise the memory referencing instruction
  // according to the opcode.
  bool success = false;
  switch (getInstructionKind(Opcode)) {
    // Move register or immediate to memory
  case InstructionKind::MOV_TO_MEM: {
    success = raiseMoveToMemInstr(MI, MemoryRefValue);
  } break;
    // Move register from memory
  case InstructionKind::MOV_FROM_MEM: {
    success = raiseMoveFromMemInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::BINARY_OP_RM: {
    success = raiseBinaryOpMemToRegInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::DIVIDE_MEM_OP: {
    success = raiseDivideInstr(MI, MemoryRefValue);
  } break;
  case InstructionKind::LOAD_FPU_REG:
    success = raiseLoadIntToFloatRegInstr(MI, MemoryRefValue);
    break;
  case InstructionKind::STORE_FPU_REG:
    success = raiseStoreIntToFloatRegInstr(MI, MemoryRefValue);
    break;
  default:
    outs() << "Unhandled memory referencing instruction.\n";
    MI.dump();
  }
  return success;
}

bool X86MachineInstructionRaiser::raiseSetCCMachineInstr(
    const MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();
  bool Success = false;

  assert(MIDesc.getNumDefs() == 1 &&
         "Not found expected one destination operand of set instruction");
  assert(MIDesc.getNumImplicitUses() == 1 &&
         MIDesc.hasImplicitUseOfPhysReg(X86::EFLAGS) &&
         "Not found expected implicit use of eflags in set instruction.");

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  const MachineOperand &DestOp = MI.getOperand(0);
  CmpInst::Predicate pred = CmpInst::Predicate::BAD_ICMP_PREDICATE;
  uint64_t EflagBit = EFLAGS::UNDEFINED;

  int cmpConst = 0;

  switch (X86::getCondFromSETCC(MI)) {
  case X86::COND_NE: {
    // Check if ZF == 0
    pred = CmpInst::Predicate::ICMP_EQ;
    cmpConst = 0;
    EflagBit = EFLAGS::ZF;
  } break;
  case X86::COND_E: {
    // Check if ZF == 1
    pred = CmpInst::Predicate::ICMP_EQ;
    cmpConst = 1;
    EflagBit = EFLAGS::ZF;
  } break;
  case X86::COND_INVALID:
    assert(false && "Set instruction with invalid condition found");
    break;
  default:
    assert(false && "Set instruction with unhandled condition found");
    break;
  }

  assert(EflagBit != EFLAGS::UNDEFINED && "Unhandled EFLAGS");

  if (pred == CmpInst::Predicate::BAD_ICMP_PREDICATE) {
    MI.dump();
    assert(false && "Unhandled set instruction");
  }

  if (DestOp.isReg()) {
    Value *EflagVal = raisedValues->getEflagReachingDef(
        EflagBit, MI.getParent()->getNumber());
    Value *cmpConstVal =
        ConstantInt::get(EflagVal->getType(), cmpConst, false /* isSigned */);
    CmpInst *cmp = new ICmpInst(pred, EflagVal, cmpConstVal);
    RaisedBB->getInstList().push_back(cmp);
    raisedValues->setPhysRegSSAValue(DestOp.getReg(),
                                     MI.getParent()->getNumber(), cmp);
    Success = true;
  } else {
    outs() << "Unhandled set instruction with memory destination\n";
    Success = false;
  }
  return Success;
}
// Raise a binary operation instruction with operand encoding I or RI
bool X86MachineInstructionRaiser::raiseBinaryOpImmToRegMachineInstr(
    const MachineInstr &MI) {
  unsigned int DstIndex = 0, SrcOp1Index = 1, SrcOp2Index = 2;
  const MCInstrDesc &MIDesc = MI.getDesc();
  int MBBNo = MI.getParent()->getNumber();

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // A binary operation instruction with encoding I specifies one operand -
  // using AL/AX/EAX/RAX as implicit register operand.
  // A binary operation instruction with encoding RI specifies two operands
  // - the first operand is a register and the second the immediate value
  //
  // The first operand is also as the destination operand.
  // X86::EFLAGS is the implicit def operand.
  unsigned NumOperands = MI.getNumExplicitOperands() +
                         MIDesc.getNumImplicitUses() +
                         MIDesc.getNumImplicitDefs();

  if (NumOperands == 4) {
    // Create a stack alloc slot corresponding to the adjusted sp value.
    if ((MIDesc.getNumDefs() == 1) &&
        (find64BitSuperReg(MI.getOperand(DstIndex).getReg()) == X86::RSP) &&
        (find64BitSuperReg(MI.getOperand(SrcOp1Index).getReg()) == X86::RSP) &&
        MI.getOperand(SrcOp2Index).isImm() &&
        MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS)) {

      // Find the stack allocation, if any, associated with the stack index
      // being changed to.
      X86AddressMode AdjSPRef;
      AdjSPRef.Base.Reg = X86::RSP;
      uint64_t Imm = MI.getOperand(SrcOp2Index).getImm();

      switch (MI.getOpcode()) {
      case X86::ADD8i8:
      case X86::ADD64i32:
      case X86::ADD16ri:
      case X86::ADD16ri8:
      case X86::ADD32ri:
      case X86::ADD32ri8:
      case X86::ADD64ri8:
      case X86::ADD64ri32:
        AdjSPRef.Disp = Imm;
        break;
      case X86::SUB32ri:
      case X86::SUB32ri8:
      case X86::SUB64ri8:
      case X86::SUB64ri32:
      case X86::SUB64i32:
        AdjSPRef.Disp = -Imm;
        break;
      default:
        assert(false && "SP computation - unhandled binary opcode instruction");
      }

      Value *StackRefVal = getStackAllocatedValue(MI, AdjSPRef, true);
      assert((StackRefVal != nullptr) && "Reference to unallocated stack slot");
      raisedValues->setPhysRegSSAValue(X86::RSP, MI.getParent()->getNumber(),
                                       StackRefVal);
    } else {
      Value *SrcOp1Value = nullptr;
      Value *SrcOp2Value = nullptr;
      unsigned int DstPReg = X86::NoRegister;

      assert(MIDesc.hasImplicitDefOfPhysReg(X86::EFLAGS) &&
             "Expected implicit def operand EFLAGS not found");

      if (MIDesc.getNumDefs() == 1) {
        const MachineOperand &DstOp = MI.getOperand(DstIndex);
        const MachineOperand &SrcOp1 = MI.getOperand(SrcOp1Index);
        const MachineOperand &SrcOp2 = MI.getOperand(SrcOp2Index);
        assert(DstOp.isReg() && "Not found expected register to be the "
                                "destination operand of BinOp instruction with "
                                "RI/I operand format");
        assert(SrcOp1.isReg() &&
               "Not found expected register to be the first "
               "operand of BinOp instruction with RI/I operand format");

        // Get value of SrcOp1
        unsigned int SrcOp1PReg = SrcOp1.getReg();
        SrcOp1Value = getRegOrArgValue(SrcOp1PReg, MI.getParent()->getNumber());

        // Get value of SrcOp2
        assert(SrcOp2.isImm() && "Expect immediate operand in a BinOp "
                                 "instruction with RI/I operand format");
        // Create constant of type that matches that of the dest operand
        Type *Ty = getPhysRegOperandType(MI, DstIndex);
        SrcOp2Value = ConstantInt::get(Ty, SrcOp2.getImm());
        assert(SrcOp1Value != nullptr && SrcOp2Value != nullptr &&
               "Undefined source values encountered in BinOp instruction with "
               "RI/I operand format");

        // Get destination reg
        DstPReg = DstOp.getReg();

        // Generate any necessary trunc or sext instrs to match the sizes
        // of source and dest operands, as needed.
        SrcOp1Value = matchSSAValueToSrcRegSize(MI, SrcOp1Index);
      } else if (MIDesc.getNumDefs() == 0) {
        SrcOp1Index = 0;
        // Uses implicit register AL/AX/EAX/RAX as source and dest
        assert(MIDesc.getNumImplicitUses() == 1 &&
               "Expected one implicit use operand of BinOp instruction with "
               "RI/I operand format");
        assert(MIDesc.getNumImplicitDefs() == 2 &&
               "Expected one implicit use operand of BinOp instruction with "
               "RI/I operand format");

        // Get the first (and only) operand
        const MachineOperand &SrcOp = MI.getOperand(SrcOp1Index);

        // Get dest reg
        DstPReg = MIDesc.ImplicitDefs[0];

        assert(((DstPReg == X86::AL) || (DstPReg == X86::AX) ||
                (DstPReg == X86::EAX) || (DstPReg == X86::RAX)) &&
               "Expected implicit use of operand AL/AX/EAX/RAX not found");

        assert(MIDesc.hasImplicitUseOfPhysReg(DstPReg) &&
               "Expected implicit use of operand AL/AX/EAX/RAX not found");

        // Get value of SrcOp1
        SrcOp1Value = getRegOrArgValue(DstPReg, MI.getParent()->getNumber());

        // Get value of SrcOp2
        assert(SrcOp.isImm() && "Expect immediate operand in a BinOp "
                                "instruction with RI/I operand format");
        // Create constant of type that matches that of the dest operand
        Type *Ty = getPhysRegType(DstPReg);
        SrcOp2Value = ConstantInt::get(Ty, SrcOp.getImm());
      } else {
        MI.dump();
        assert(false && "Unhandled binary operation instruction with RI/I "
                        "operand format");
      }

      assert(DstPReg != X86::NoRegister &&
             "Failed to determine destination register of BinOp instruction "
             "with RI/I operand format");

      assert(SrcOp1Value != nullptr && SrcOp2Value != nullptr &&
             "Undefined source values encountered in BinOp instruction with "
             "RI/I operand format");

      Instruction *BinOpInstr = nullptr;
      switch (MI.getOpcode()) {
      case X86::ADD8i8:
      case X86::ADD16ri:
      case X86::ADD16ri8:
      case X86::ADD32ri:
      case X86::ADD32ri8:
      case X86::ADD64ri8:
      case X86::ADD64ri32:
      case X86::ADD64i32: {
        // Generate add instruction
        BinOpInstr = BinaryOperator::CreateAdd(SrcOp1Value, SrcOp2Value);
        // Clear OF and CF
        raisedValues->setEflagValue(EFLAGS::OF, MBBNo, false);
        raisedValues->setEflagValue(EFLAGS::CF, MBBNo, false);
      } break;
      case X86::SUB32ri:
      case X86::SUB32ri8:
      case X86::SUB64ri8:
      case X86::SUB64ri32:
      case X86::SUB64i32:
        // Generate sub instruction
        BinOpInstr = BinaryOperator::CreateSub(SrcOp1Value, SrcOp2Value);
        break;
      case X86::AND8i8:
      case X86::AND8ri:
      case X86::AND16ri:
      case X86::AND16ri8:
      case X86::AND32ri:
      case X86::AND32ri8:
      case X86::AND64ri8:
      case X86::AND64ri32:
        // Generate and instruction
        BinOpInstr = BinaryOperator::CreateAnd(SrcOp1Value, SrcOp2Value);
        break;
      case X86::OR32ri:
      case X86::OR32ri8:
        // Generate or instruction
        BinOpInstr = BinaryOperator::CreateOr(SrcOp1Value, SrcOp2Value);
        break;
      case X86::XOR8ri:
        // Generate xor instruction
        BinOpInstr = BinaryOperator::CreateXor(SrcOp1Value, SrcOp2Value);
        break;
      case X86::IMUL32rri8:
      case X86::IMUL64rri8:
      case X86::IMUL64rri32:
        BinOpInstr = BinaryOperator::CreateMul(SrcOp1Value, SrcOp2Value);
        break;
      case X86::SHR8ri:
      case X86::SHR16ri:
      case X86::SHR32ri:
      case X86::SHR64ri:
        // Generate shr instruction
        BinOpInstr = BinaryOperator::CreateLShr(SrcOp1Value, SrcOp2Value);
        break;
      case X86::SHL8ri:
      case X86::SHL16ri:
      case X86::SHL32ri:
      case X86::SHL64ri:
        // Generate shl instruction
        BinOpInstr = BinaryOperator::CreateShl(SrcOp1Value, SrcOp2Value);
        break;
      case X86::SAR8ri:
      case X86::SAR16ri:
      case X86::SAR32ri:
      case X86::SAR64ri:
        // Generate shr instruction
        BinOpInstr = BinaryOperator::CreateLShr(SrcOp1Value, SrcOp2Value);
        break;
      default:
        assert(false && "Unhandled reg to imm binary operator instruction");
        break;
      }

      RaisedBB->getInstList().push_back(BinOpInstr);
      raisedValues->testAndSetEflagSSAValue(EFLAGS::CF, MBBNo, BinOpInstr);
      raisedValues->testAndSetEflagSSAValue(EFLAGS::ZF, MBBNo, BinOpInstr);

      // Update PhysReg to Value map
      raisedValues->setPhysRegSSAValue(DstPReg, MI.getParent()->getNumber(),
                                       BinOpInstr);
    }
  } else {
    MI.dump();
    assert(false && "Unhandled add imeediate instruction");
  }
  return true;
}

// Raise indirect branch instruction.
bool X86MachineInstructionRaiser::raiseIndirectBranchMachineInstr(
    ControlTransferInfo *CTRec) {
  const MachineInstr *MI = CTRec->CandidateMachineInstr;
  BasicBlock *CandBB = CTRec->CandidateBlock;

  const MCInstrDesc &MCID = MI->getDesc();

  // Make sure this function was called on a direct branch instruction.
  assert((MCID.TSFlags & X86II::ImmMask) == 0 &&
         "PC-Relative control transfer not expected");

  if (MI->getOperand(0).isJTI()) {
    unsigned jtIndex = MI->getOperand(0).getIndex();
    std::vector<JumpTableBlock> JTCases;
    const MachineJumpTableInfo *MJT = MF.getJumpTableInfo();
    MachineModuleInfo &mmi = MF.getMMI();
    const Module *md = mmi.getModule();
    LLVMContext &Ctx = md->getContext();

    std::vector<MachineJumpTableEntry> JumpTables = MJT->getJumpTables();
    for (unsigned j = 0, f = JumpTables[jtIndex].MBBs.size(); j != f; ++j) {
      llvm::Type *i32_type = llvm::IntegerType::getInt32Ty(Ctx);
      llvm::ConstantInt *i32_val =
          cast<ConstantInt>(llvm::ConstantInt::get(i32_type, j, true));
      MachineBasicBlock *Succ = JumpTables[jtIndex].MBBs[j];
      ConstantInt *CaseVal = i32_val;
      JTCases.push_back(std::make_pair(CaseVal, Succ));
    }

    // Create the Switch Instruction
    unsigned int numCases = JTCases.size();
    auto intr_df = mbbToBBMap.find(jtList[jtIndex].df_MBB->getNumber());
    MachineBasicBlock *cdMBB = jtList[jtIndex].conditionMBB;
    Instruction *cdi = raiseConditonforJumpTable(*cdMBB);
    assert(cdi != nullptr && "Condition value is NUll!");

    BasicBlock *df_bb = intr_df->second;
    SwitchInst *Inst = SwitchInst::Create(cdi, df_bb, numCases);

    for (unsigned i = 0, e = numCases; i != e; ++i) {
      MachineBasicBlock *Mbb = JTCases[i].second;
      auto intr = mbbToBBMap.find(Mbb->getNumber());
      BasicBlock *bb = intr->second;
      Inst->addCase(JTCases[i].first, bb);
    }

    CandBB->getInstList().push_back(Inst);
    CTRec->Raised = true;
  }
  return true;
}

// Raise direct branch instruction.
bool X86MachineInstructionRaiser::raiseDirectBranchMachineInstr(
    ControlTransferInfo *CTRec) {
  const MachineInstr *MI = CTRec->CandidateMachineInstr;
  BasicBlock *CandBB = CTRec->CandidateBlock;

  const MCInstrDesc &MCID = MI->getDesc();

  // Make sure this function was called on a direct branch instruction.
  assert(X86II::isImmPCRel(MCID.TSFlags) &&
         "PC-Relative control transfer expected");

  // Get branch offset of the branch instruction
  const MachineOperand &MO = MI->getOperand(0);
  assert(MO.isImm() && "Expected immediate operand not found");
  int64_t BranchOffset = MO.getImm();
  MCInstRaiser *MCIR = getMCInstRaiser();
  // Get MCInst offset - the offset of machine instruction in the binary
  uint64_t MCInstOffset = MCIR->getMCInstIndex(*MI);

  assert(MCIR != nullptr && "MCInstRaiser not initialized");
  int64_t BranchTargetOffset =
      MCInstOffset + MCIR->getMCInstSize(MCInstOffset) + BranchOffset;
  const int64_t TgtMBBNo = MCIR->getMBBNumberOfMCInstOffset(BranchTargetOffset);
  assert((TgtMBBNo != -1) && "No branch target found");
  auto iter = mbbToBBMap.find(TgtMBBNo);
  assert(iter != mbbToBBMap.end() &&
         "BasicBlock corresponding to MachineInstr branch not found");
  BasicBlock *TgtBB = (*iter).second;
  if (MI->isUnconditionalBranch()) {
    // Just create a branch instruction targeting TgtBB
    BranchInst *UncondBr = BranchInst::Create(TgtBB);
    CandBB->getInstList().push_back(UncondBr);
    CTRec->Raised = true;
  } else if (MI->isConditionalBranch()) {
    // Find the fall through basic block
    MCInstRaiser::const_mcinst_iter MCIter = MCIR->getMCInstAt(MCInstOffset);
    LLVMContext &Ctx(MF.getFunction().getContext());
    // Go to next instruction
    MCIter++;
    assert(MCIter != MCIR->const_mcinstr_end() &&
           "Attempt to go past MCInstr stream");
    // Get MBB number whose lead instruction is at the offset of next
    // instruction. This is the fall-through MBB.
    int64_t FTMBBNum = MCIR->getMBBNumberOfMCInstOffset((*MCIter).first);
    assert((FTMBBNum != -1) && "No fall-through target found");
    // Find raised BasicBlock corresponding to fall-through MBB
    auto mapIter = mbbToBBMap.find(FTMBBNum);
    assert(mapIter != mbbToBBMap.end() &&
           "Fall-through BasicBlock corresponding to MachineInstr branch not "
           "found");
    BasicBlock *FTBB = (*mapIter).second;
    // Get the condition value
    assert(CTRec->RegValues.size() == EFlagBits.size() &&
           "Unexpected number of ELFAGS bit values in conditional branch not "
           "handled");

    // Branch condition value
    Value *BranchCond = nullptr;
    // Predicate operation to be performed
    CmpInst::Predicate Pred = CmpInst::Predicate::BAD_ICMP_PREDICATE;
    Value *TrueValue = ConstantInt::getTrue(Ctx);
    Value *FalseValue = ConstantInt::getFalse(Ctx);
    auto Opcode = MI->getOpcode();
    assert(((Opcode == X86::JCC_1) || (Opcode == X86::JCC_2) ||
            (Opcode == X86::JCC_4)) &&
           "Conditional branch instruction expected");
    X86::CondCode CC = X86::COND_INVALID;

    // Unfortunately X86::getCondFromBranch(MI) only looks at JCC_1. We need to
    // handle JCC_2 and JCC_4 as well.
    switch (MI->getOpcode()) {
    default:
      CC = X86::COND_INVALID;
      break;
    case X86::JCC_1:
    case X86::JCC_2:
    case X86::JCC_4:
      CC = static_cast<X86::CondCode>(
          MI->getOperand(MI->getDesc().getNumOperands() - 1).getImm());
    }

    switch (CC) {
    case X86::COND_E: {
      // Test ZF == 1
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising JE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      BranchCond = new ICmpInst(Pred, ZFValue, TrueValue);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_NE: {
      // Test ZF == 0
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      assert(ZFValue != nullptr &&
             "Failed to get EFLAGS value while raising JNE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      BranchCond = new ICmpInst(Pred, ZFValue, FalseValue);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_S: {
      // Test SF == 1
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      assert(SFValue != nullptr &&
             "Failed to get EFLAGS value while raising JS");

      Pred = CmpInst::Predicate::ICMP_EQ;
      // Construct a compare instruction
      BranchCond = new ICmpInst(Pred, SFValue, TrueValue);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
#if 0
    // TODO: set EFLAGS appropriately
    case X86::COND_A:
      break;
#endif
    case X86::COND_AE: {
      // CF = 0
      int CFIndex = getEflagBitIndex(EFLAGS::CF);
      Value *CFValue = CTRec->RegValues[CFIndex];
      assert(CFValue != nullptr &&
             "Failed to get EFLAGS value while raising JAE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare CF = 0
      BranchCond = new ICmpInst(Pred, CFValue, FalseValue, "CFCmp_JAE");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
#if 0
    case X86::COND_B:
      break;
    case X86::COND_BE:
      break;
#endif
    case X86::COND_G: {
      // ZF == 0 and (SF == OF)
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      Instruction *ZFCond = nullptr;
      Instruction *SFOFCond = nullptr;
      assert(((ZFValue != nullptr) && (SFValue != nullptr) &&
              (OFValue != nullptr)) &&
             "Improper ELFAGS Values for JLE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare ZF and 0
      ZFCond = new ICmpInst(Pred, ZFValue, FalseValue, "ZFCmp_JG");
      CandBB->getInstList().push_back(ZFCond);
      // Test SF == OF
      SFOFCond = new ICmpInst(Pred, SFValue, OFValue, "SFOFCmp_JG");
      CandBB->getInstList().push_back(SFOFCond);
      BranchCond = BinaryOperator::CreateAnd(ZFCond, SFOFCond, "ZFAndSFOF_JG");
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_GE: {
      // SF == OF
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      assert(SFValue != nullptr && OFValue != nullptr &&
             "Failed to get EFLAGS value while raising JGE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare SF and OF
      BranchCond = new ICmpInst(Pred, SFValue, OFValue);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_L: {
      // SF != OF
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      assert(((SFValue != nullptr) && (OFValue != nullptr)) &&
             "Improper ELFAGS Values for JL");
      // Test SF != OF
      Pred = CmpInst::Predicate::ICMP_NE;
      // Compare SF and OF
      BranchCond = new ICmpInst(Pred, SFValue, OFValue);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_LE: {
      // ZF == 1 or (SF != OF)
      int ZFIndex = getEflagBitIndex(EFLAGS::ZF);
      int SFIndex = getEflagBitIndex(EFLAGS::SF);
      int OFIndex = getEflagBitIndex(EFLAGS::OF);
      Value *ZFValue = CTRec->RegValues[ZFIndex];
      Value *SFValue = CTRec->RegValues[SFIndex];
      Value *OFValue = CTRec->RegValues[OFIndex];
      Instruction *ZFCond = nullptr;
      Instruction *SFOFCond = nullptr;
      assert(((ZFValue != nullptr) && (SFValue != nullptr) &&
              (OFValue != nullptr)) &&
             "Improper ELFAGS Values for JLE");
      Pred = CmpInst::Predicate::ICMP_EQ;
      // Compare ZF and 1
      ZFCond = new ICmpInst(Pred, ZFValue, TrueValue);
      CandBB->getInstList().push_back(ZFCond);
      // Test SF != OF
      Pred = CmpInst::Predicate::ICMP_NE;
      // Compare SF and OF
      SFOFCond = new ICmpInst(Pred, SFValue, OFValue);
      CandBB->getInstList().push_back(SFOFCond);
      BranchCond = BinaryOperator::CreateOr(ZFCond, SFOFCond);
      CandBB->getInstList().push_back(dyn_cast<Instruction>(BranchCond));
    } break;
    case X86::COND_INVALID:
      assert(false && "Invalid condition on branch");
      break;
    default:
      MI->dump();
      assert(false && "Unhandled conditional branch");
    }

    // Create branch instruction
    BranchInst *CondBr = BranchInst::Create(TgtBB, FTBB, BranchCond);
    CandBB->getInstList().push_back(CondBr);
    CTRec->Raised = true;
  } else {
    assert(false && "Unhandled type of branch instruction");
  }
  return true;
}

// Raise a generic instruction. This is the catch all MachineInstr raiser
bool X86MachineInstructionRaiser::raiseGenericMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();
  bool success = false;

  // Now raise the instruction according to the opcode kind
  switch (getInstructionKind(Opcode)) {
  case InstructionKind::BINARY_OP_WITH_IMM:
    success = raiseBinaryOpImmToRegMachineInstr(MI);
    break;
  case InstructionKind::CONVERT_BWWDDQ:
    success = raiseConvertBWWDDQMachineInstr(MI);
    break;
  case InstructionKind::CONVERT_WDDQQO:
    success = raiseConvertWDDQQOMachineInstr(MI);
    break;
  case InstructionKind::LEA_OP:
    success = raiseLEAMachineInstr(MI);
    break;
  case InstructionKind::MOV_RR:
    success = raiseMoveRegToRegMachineInstr(MI);
    break;
  case InstructionKind::MOV_RI:
    success = raiseMoveImmToRegMachineInstr(MI);
    break;
  case InstructionKind::BINARY_OP_RR:
    success = raiseBinaryOpRegToRegMachineInstr(MI);
    break;
  case InstructionKind::SETCC:
    success = raiseSetCCMachineInstr(MI);
    break;
  case InstructionKind::COMPARE:
    success = raiseCompareMachineInstr(MI, false, nullptr);
    break;
  case InstructionKind::FPU_REG_OP:
    success = raiseFPURegisterOpInstr(MI);
    break;
  case InstructionKind::DIVIDE_REG_OP: {
    const MachineOperand &SrcOp = MI.getOperand(0);
    assert(SrcOp.isReg() &&
           "Expect register source operand of a div instruction");
    Value *SrcVal =
        getRegOrArgValue(SrcOp.getReg(), MI.getParent()->getNumber());
    success = raiseDivideInstr(MI, SrcVal);
  } break;
  default: {
    outs() << "*** Generic instruction not raised : ";
    MI.dump();
    success = false;
  }
  }
  return success;
}

// Raise a return instruction.
bool X86MachineInstructionRaiser::raiseReturnMachineInstr(
    const MachineInstr &MI) {
  Type *RetType = raisedFunction->getReturnType();
  Value *RetValue = nullptr;

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  if (!RetType->isVoidTy()) {
    unsigned int retReg =
        (RetType->getPrimitiveSizeInBits() == 64) ? X86::RAX : X86::EAX;
    RetValue =
        raisedValues->getReachingDef(retReg, MI.getParent()->getNumber());
  }
  // Create return instruction
  Instruction *retInstr =
      ReturnInst::Create(MF.getFunction().getContext(), RetValue);
  RaisedBB->getInstList().push_back(retInstr);

  return true;
}

bool X86MachineInstructionRaiser::raiseBranchMachineInstrs() {
  if (PrintPass) {
    outs() << "CFG : Before Raising Terminator Instructions\n";
    raisedFunction->dump();
  }

  // Raise branch instructions with control transfer records
  bool success = true;
  for (ControlTransferInfo *CTRec : CTInfo) {
    if (CTRec->CandidateMachineInstr->isBranch()) {
      const MachineInstr *MI = CTRec->CandidateMachineInstr;
      const MCInstrDesc &MCID = MI->getDesc();
      uint64_t imm = MCID.TSFlags & X86II::ImmMask;

      if ((imm == X86II::Imm8PCRel) || (imm == X86II::Imm16PCRel) ||
          (imm == X86II::Imm32PCRel)) {
        success &= raiseDirectBranchMachineInstr(CTRec);
        assert(success && "Failed to raise direct branch instruction");
      } else {
        success &= raiseIndirectBranchMachineInstr(CTRec);
        assert(success && "Failed to raise indirect branch instruction");
      }
    }
  }

  // Delete all ControlTransferInfo records of branch instructions
  // that were raised.
  if (!CTInfo.empty()) {
    CTInfo.erase(
        std::remove_if(CTInfo.begin(), CTInfo.end(),
                       [](const ControlTransferInfo *r) { return r->Raised; }),
        CTInfo.end());
  }
  assert(CTInfo.empty() && "Unhandled branch instructions exist");

  // Note that for basic blocks that fall-through and have no terminator,
  // no control transfer record is created. Insert branch instructions
  // at the end of all such blocks.

  // Walk basic blocks of the MachineFunction.
  for (MachineFunction::iterator mfIter = MF.begin(), mfEnd = MF.end();
       mfIter != mfEnd; mfIter++) {
    MachineBasicBlock &MBB = *mfIter;
    // Get the number of MachineBasicBlock being looked at.
    // If MBB has no terminators, insert a branch to the fall through edge.
    if (MBB.getFirstTerminator() == MBB.end()) {
      if (MBB.succ_size() > 0) {
        // Find the BasicBlock corresponding to MBB
        auto iter = mbbToBBMap.find(MBB.getNumber());
        assert(iter != mbbToBBMap.end() &&
               "Unable to find BasicBlock to insert unconditional branch");
        BasicBlock *BB = iter->second;

        // Find the BasicBlock corresponding to the successor of MBB
        MachineBasicBlock *SuccMBB = *(MBB.succ_begin());
        iter = mbbToBBMap.find(SuccMBB->getNumber());
        assert(iter != mbbToBBMap.end() &&
               "Unable to find successor BasicBlock");
        BasicBlock *SuccBB = iter->second;

        // Create a branch instruction targeting SuccBB
        BranchInst *UncondBr = BranchInst::Create(SuccBB);
        BB->getInstList().push_back(UncondBr);
      }
    }
  }
  if (PrintPass) {
    outs() << "CFG : After Raising Terminator Instructions\n";
    raisedFunction->dump();
  }

  return true;
}

// Raise FPU instructions
bool X86MachineInstructionRaiser::raiseFPURegisterOpInstr(
    const MachineInstr &MI) {

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  // Construct the appropriate instruction
  unsigned Opcode = MI.getOpcode();
  switch (Opcode) {
  case X86::MUL_FPrST0:
  case X86::DIV_FPrST0: {
    Value *St0Val = FPURegisterStackGetValueAt(0);
    assert((St0Val != nullptr) && "Failed to get ST(0) value");
    Type *St0ValTy = St0Val->getType();
    assert(St0ValTy->isFloatingPointTy() &&
           "Unexpected non-FP value on FPU register stack");
    assert((MI.getNumExplicitOperands() == 1) &&
           "Unexpected number of operands in FP register op instruction "
           "format");
    const MachineOperand &StRegOp = MI.getOperand(0);
    assert(StRegOp.isReg() &&
           "Unexpected non-register operand of FP register op instruction");
    int8_t FPRegIndex = StRegOp.getReg() - X86::ST0;
    assert((FPRegIndex >= 0) && (FPRegIndex < FPUSTACK_SZ) &&
           "Unexpected FPU register stack index computed");
    Value *StVal = FPURegisterStackGetValueAt(FPRegIndex);
    assert((StVal != nullptr) && "Failed to get value of FPU register");
    if (StVal->getType() != St0ValTy) {
      CastInst *CInst = CastInst::Create(
          CastInst::getCastOpcode(StVal, false, St0ValTy, false), StVal,
          St0ValTy);
      RaisedBB->getInstList().push_back(CInst);
      StVal = CInst;
    }
    // Create fmul
    Instruction *FPRegOpInstr = nullptr;
    if (Opcode == X86::MUL_FPrST0) {
      FPRegOpInstr = BinaryOperator::CreateFMul(StVal, St0Val);
    } else if (Opcode == X86::DIV_FPrST0) {
      FPRegOpInstr = BinaryOperator::CreateFDiv(StVal, St0Val);
    }
    RaisedBB->getInstList().push_back(FPRegOpInstr);
    // Update the FP register FPRegIndex with FPRegOpInstr
    FPURegisterStackSetValueAt(FPRegIndex, FPRegOpInstr);
    // Pop FPU register stack
    FPURegisterStackPop();
  } break;
  default: {
    assert(false && "Unhandled FPU instruction");
  } break;
  }

  return true;
}

// Raise Call instruction
bool X86MachineInstructionRaiser::raiseCallMachineInstr(
    const MachineInstr &MI) {
  unsigned int Opcode = MI.getOpcode();

  // Get the BasicBlock corresponding to MachineBasicBlock of MI.
  // Raised instruction is added to this BasicBlock.
  BasicBlock *RaisedBB = getRaisedBasicBlock(MI.getParent());

  bool Success = false;
  switch (Opcode) {
    // case X86::CALLpcrel16   :
    // case X86::CALLpcrel32   :
  case X86::CALL64pcrel32:
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
    Function *CalledFunc = nullptr;
    uint64_t MCInstSize = MCIR->getMCInstSize(MCInstOffset);
    // First check if PC-relative call target embedded in the call
    // instruction can be used to get called function.
    int64_t CallTargetIndex = MCInstOffset + MR->getTextSectionAddress() +
                              MCInstSize + RelCallTargetOffset;
    // Get the function at index CalltargetIndex
    CalledFunc = MR->getFunctionAt(CallTargetIndex);
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

    std::vector<Value *> CallInstFuncArgs;
    unsigned NumArgs = CalledFunc->arg_size();
    Argument *CalledFuncArgs = CalledFunc->arg_begin();

    if (CalledFunc->isVarArg()) {
      // Discover argument registers that are live just before the CallMI.
      // Liveness of the blocks is already computed in
      // getRaisedFunctionPrototype(). So no need to run it again since no
      // MBB would be modified.
      // MachineBasicBlock::const_reverse_iterator CallInstIter(MI);
      // Find the highest argument register that is defined in the block
      // before the CallMI. NOTE : We assume that all arguments are setup
      // prior to the call. This argument setup manifests as defines in the
      // block or a combination of argument registers that are live-in and
      // defines in the block. Additionally, if the block has more than one
      // calls, it is assumed that call setup for all calls other than the
      // first is done entirely in the block after the preceding call. In
      // such a situation, there is no need to look for argument registers
      // in the live-ins of the block.

      // Bit mask to keep track of argument register positions already
      // discovered.
      uint8_t PositionMask = 0;

      const MachineBasicBlock *CurMBB = MI.getParent();
      // If an argument register does not have a definition in a block that has
      // a call instruction between block entry and MI, there is no need (and is
      // not correct) to look for a reaching definition in its predecessors.
      bool HasCallInst = false;
      unsigned int ArgNo = 1;
      // Find if CurMBB has call between block entry and MI

      for (auto ArgReg : GPR64ArgRegs64Bit) {
        if (hasPhysRegDefInBlock(ArgReg, &MI, CurMBB, MCID::Call, HasCallInst))
          PositionMask |= (1 << ArgNo);
        else if (!HasCallInst) {
          // Look to see if the argument register has a reaching definition in
          // the predecessors of CurMBB.
          unsigned int ReachDefPredEdgeCount = 0;

          for (auto P : CurMBB->predecessors()) {
            SmallVector<MachineBasicBlock *, 8> WorkList;
            // No blocks visited in this walk up the predecessor P
            BitVector BlockVisited(MF.getNumBlockIDs(), false);

            // Start at predecessor P
            WorkList.push_back(P);

            while (!WorkList.empty()) {
              MachineBasicBlock *PredMBB = WorkList.pop_back_val();
              if (!BlockVisited[PredMBB->getNumber()]) {
                // Mark block as visited
                BlockVisited.set(PredMBB->getNumber());
                // Need to consider definitions after any call instructions in
                // the block. This is the reason we can not use
                // getReachingDefs() which does not consider the position where
                // the register is defined.
                bool Ignored;
                if (hasPhysRegDefInBlock(ArgReg, nullptr, PredMBB, MCID::Call,
                                         Ignored))
                  ReachDefPredEdgeCount++;
                else {
                  // Reach info not found, continue walking the predecessors of
                  // CurBB.
                  for (auto P : PredMBB->predecessors()) {
                    // push_back the block which was not visited.
                    if (!BlockVisited[P->getNumber()])
                      WorkList.push_back(P);
                  }
                }
              } else if (PredMBB->getNumber() == CurMBB->getNumber())
                // This is a loop. Simply increment ReachDefPredEdgeCount to
                // indicate that we have a reaching def.
                ReachDefPredEdgeCount++;
            }
          }
          // If there is a reaching def on all predecessor edges then consider
          // it as an argument used by the variadic function.
          if ((ReachDefPredEdgeCount > (unsigned)0) &&
              (ReachDefPredEdgeCount == CurMBB->pred_size()))
            PositionMask |= (1 << ArgNo);
        }
        ArgNo++;
      }

      // Find the number of arguments
      // NOTE: Handling register arguments - 6 in number. Need to handle
      // arguments passed on stack make sure bit 8 and bit 0 are not set
      assert(!(PositionMask & 1) && !(PositionMask & (1 << 7)) &&
             "Invalid number of arguments discovered");
      uint8_t ShftPositionMask = PositionMask >> 1;
      uint8_t NumArgsDiscovered = 0;
      // Consider only consecutive argument registers.
      while (ShftPositionMask & 1) {
        ShftPositionMask = ShftPositionMask >> 1;
        NumArgsDiscovered++;
      }
      // If number of arguments discovered is greater than CalledFunc
      // arguments use that as the number of arguments of the called
      // function.
      if (NumArgsDiscovered > NumArgs) {
        NumArgs = NumArgsDiscovered;
      }
    }
    // Construct the argument list with values to be used to construct a new
    // CallInst. These values are those of the physical registers as defined
    // in C calling convention (the calling convention currently supported).
    for (unsigned i = 0; i < NumArgs; i++) {
      // Get the values of argument registers
      // Do not match types since we are explicitly using 64-bit GPR array. Any
      // necessary casting will be done later in this function.
      Value *ArgVal =
          getRegOrArgValue(GPR64ArgRegs64Bit[i], MI.getParent()->getNumber());
      // This condition will not be true for varargs of a variadic function.
      // In that case just add the value.
      if (i < CalledFunc->arg_size()) {
        // If the ConstantInt value is being treated as a pointer (i.e., is
        // an address, try to construct the associated global read-only data
        // value.
        Argument &FuncArg = CalledFuncArgs[i];
        if (isa<ConstantInt>(ArgVal)) {
          ConstantInt *Address = dyn_cast<ConstantInt>(ArgVal);
          if (!Address->isNegative()) {
            Value *RefVal =
                const_cast<Value *>(getOrCreateGlobalRODataValueAtOffset(
                    Address->getSExtValue(), Address->getType()));
            if (RefVal != nullptr) {
              assert(RefVal->getType()->isPointerTy() &&
                     "Non-pointer type of global value abstracted from "
                     "address");
              ArgVal = RefVal;
            }
          }
        }
        if (ArgVal->getType() != FuncArg.getType()) {
          CastInst *CInst = CastInst::Create(
              CastInst::getCastOpcode(ArgVal, false, FuncArg.getType(), false),
              ArgVal, FuncArg.getType());
          RaisedBB->getInstList().push_back(CInst);
          ArgVal = CInst;
        }
      }
      assert(ArgVal != nullptr && "Unexpected null argument value");
      CallInstFuncArgs.push_back(ArgVal);
    }

    // Construct call inst.
    CallInst *callInst =
        CallInst::Create(CalledFunc, ArrayRef<Value *>(CallInstFuncArgs));

    // If this is a branch being turned to a tail call set the flag
    // accordingly.
    if (MI.isBranch())
      callInst->setTailCall(true);

    RaisedBB->getInstList().push_back(callInst);
    // A function call with a non-void return will modify
    // RAX.
    Type *RetType = CalledFunc->getReturnType();
    if (!RetType->isVoidTy()) {
      raisedValues->setPhysRegSSAValue(X86::RAX, MI.getParent()->getNumber(),
                                       callInst);
    }
    if (MI.isBranch()) {
      // Emit ret void since there will be no ret instruction in the binary
      Instruction *RetInstr = ReturnInst::Create(MF.getFunction().getContext());
      RaisedBB->getInstList().push_back(RetInstr);
    }
    Success = true;
  } break;
  default: {
    assert(false && "Unhandled call instruction");
  } break;
  }

  return Success;
}

// Top-level function that calls appropriate function that raises
// a MachineInstruction.
// Returns true upon success.

bool X86MachineInstructionRaiser::raiseMachineInstr(MachineInstr &MI) {
  const MCInstrDesc &MIDesc = MI.getDesc();

  if (MIDesc.mayLoad() || MIDesc.mayStore()) {
    return raiseMemRefMachineInstr(MI);
  } else if (MIDesc.isReturn()) {
    return raiseReturnMachineInstr(MI);
  } else {
    return raiseGenericMachineInstr(MI);
  }
  return false;
}

// Raise MachineInstr in MachineFunction to MachineInstruction

bool X86MachineInstructionRaiser::raiseMachineFunction() {
  Function *CurFunction = getRaisedFunction();
  LLVMContext &Ctx(CurFunction->getContext());

  // Raise the jumptable
  raiseMachineJumpTable();

  // Initialize the raised value tracking mechanism.
  raisedValues = new X86RaisedValueTracker(this);

  Value *Zero64BitValue =
      ConstantInt::get(Type::getInt64Ty(Ctx), 0, false /* isSigned */);

  // Start with an assumption that value of EFLAGS is 0 at the
  // entry of each function.
  for (auto b : EFlagBits)
    // raisedValues->setPhysRegSSAValue(b, 0, Zero1BitValue);
    raisedValues->setEflagValue(b, 0, false);

  // Set values of some registers that appear to be used in main function to
  // 0.
  if (CurFunction->getName().equals("main")) {
    raisedValues->setPhysRegSSAValue(X86::RCX, 0, Zero64BitValue);
  }

  // Walk basic blocks of the MachineFunction in LoopTraversal - except that
  // do not walk the block coming from back edge.By performing this
  // traversal, the idea is to make sure predecessors are translated before
  // a block.

  // Raise all non control transfer MachineInstrs of each MachineBasicBlocks
  // of MachineFunction, except branch instructions.
  LoopTraversal Traversal;
  LoopTraversal::TraversalOrder TraversedMBBOrder = Traversal.traverse(MF);
  for (LoopTraversal::TraversedMBBInfo TraversedMBB : TraversedMBBOrder) {
    // Only perform the primary pass as we do not want to translate one
    // block more than once.
    if (!TraversedMBB.PrimaryPass)
      continue;
    MachineBasicBlock &MBB = *(TraversedMBB.MBB);
    // Get the number of MachineBasicBlock being looked at.
    int MBBNo = MBB.getNumber();
    // Name of the corresponding BasicBlock to be created
    std::string BBName = MBBNo == 0 ? "entry" : "bb." + std::to_string(MBBNo);
    // Create a BasicBlock instance corresponding to MBB being looked at.
    // The raised form of MachineInstr of MBB will be added to curBlock.
    BasicBlock *CurIBB = BasicBlock::Create(Ctx, BBName, CurFunction);
    // Record the mapping of the number of MBB to corresponding BasicBlock.
    // This information is used to raise branch instructions, if any, of the
    // MBB in a later walk of MachineBasicBlocks of MF.
    mbbToBBMap.insert(std::make_pair(MBBNo, CurIBB));
    // Walk MachineInsts of the MachineBasicBlock
    for (MachineBasicBlock::iterator mbbIter = MBB.instr_begin(),
                                     mbbEnd = MBB.instr_end();
         mbbIter != mbbEnd; mbbIter++) {
      MachineInstr &MI = *mbbIter;
      // Ignore noop instructions.
      if (isNoop(MI.getOpcode())) {
        continue;
      }
      // If this is a terminator instruction, record
      // necessary information to raise it in a later pass.
      if (MI.isTerminator() && !MI.isReturn()) {
        recordMachineInstrInfo(MI);
        continue;
      }
      if (MI.isCall()) {
        if (!raiseCallMachineInstr(MI)) {
          return false;
        }
      } else if (!raiseMachineInstr(MI)) {
        return false;
      }
    }
  }
  if (adjustStackAllocatedObjects()) {
    return raiseBranchMachineInstrs() && handleUnpromotedReachingDefs();
  }

  return false;
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
bool X86MachineInstructionRaiser::raise() { return raiseMachineFunction(); }

/* NOTE : The following X86ModuleRaiser class function is defined here as
 * they reference MachineFunctionRaiser class that has a forward declaration
 * in ModuleRaiser.h.
 */
// Create a new MachineFunctionRaiser object and add it to the list of
// MachineFunction raiser objects of this module.
MachineFunctionRaiser *X86ModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *f, const ModuleRaiser *mr, uint64_t start, uint64_t end) {
  MachineFunctionRaiser *mfRaiser = new MachineFunctionRaiser(
      *M, mr->getMachineModuleInfo()->getOrCreateMachineFunction(*f), mr, start,
      end);
  mfRaiser->setMachineInstrRaiser(new X86MachineInstructionRaiser(
      mfRaiser->getMachineFunction(), mr, mfRaiser->getMCInstRaiser()));
  mfRaiserVector.push_back(mfRaiser);
  return mfRaiser;
}
