//===- ARMFunctionPrototype.h -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMFunctionPrototype class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMFunctionPrototype.h"
#include "ARMSubtarget.h"
#include "llvm/CodeGen/MachineModuleInfo.h"

using namespace llvm;

char ARMFunctionPrototype::ID = 0;

ARMFunctionPrototype::ARMFunctionPrototype() : MachineFunctionPass(ID) {
  PrintPass =
      (cl::getRegisteredOptions()["print-after-all"]->getNumOccurrences() > 0);
}

ARMFunctionPrototype::~ARMFunctionPrototype() {}

/// Check the first reference of the reg is USE.
bool ARMFunctionPrototype::isUsedRegiser(unsigned reg,
                                         const MachineBasicBlock &mbb) {
  for (MachineBasicBlock::const_iterator ii = mbb.begin(), ie = mbb.end();
       ii != ie; ++ii) {
    const MachineInstr &mi = *ii;
    for (MachineInstr::const_mop_iterator oi = mi.operands_begin(),
                                          oe = mi.operands_end();
         oi != oe; oi++) {
      const MachineOperand &mo = *oi;
      if (mo.isReg() && (mo.getReg() == reg))
        return mo.isUse();
    }
  }

  return false;
}

/// Check the first reference of the reg is DEF.
void ARMFunctionPrototype::genParameterTypes(std::vector<Type *> &paramTypes,
                                             const MachineFunction &mf,
                                             LLVMContext &ctx) {
  assert(!mf.empty() && "The function body is empty!!!");

  const MachineBasicBlock &fmbb = mf.front();
  // TODO: Need to track register liveness on CFG.

  DenseMap<int, Type *> tarr;
  int maxidx = -1; // When the maxidx is -1, means there is no argument.

  // The first function argument is from R0.
  if (isUsedRegiser(ARM::R0, fmbb)) {
    maxidx = 0;
    tarr[maxidx] = Type::getInt32Ty(ctx);
  }

  // The second function argument is from R1.
  if (isUsedRegiser(ARM::R1, fmbb)) {
    maxidx = 1;
    tarr[maxidx] = Type::getInt32Ty(ctx);
  }

  // The third function argument is from R2.
  if (isUsedRegiser(ARM::R2, fmbb)) {
    maxidx = 2;
    tarr[maxidx] = Type::getInt32Ty(ctx);
  }

  // The fourth function argument is from R3.
  if (isUsedRegiser(ARM::R3, fmbb)) {
    maxidx = 3;
    tarr[maxidx] = Type::getInt32Ty(ctx);
  }

  // The rest of function arguments are from stack.
  for (MachineFunction::const_iterator mbbi = mf.begin(), mbbe = mf.end();
       mbbi != mbbe; ++mbbi) {
    const MachineBasicBlock &mbb = *mbbi;

    for (MachineBasicBlock::const_iterator mii = mbb.begin(), mie = mbb.end();
         mii != mie; ++mii) {
      const MachineInstr &mi = *mii;

      // Match pattern like ldr r1, [fp, #8].
      if (mi.getOpcode() == ARM::LDRi12 && mi.getNumOperands() > 2) {
        const MachineOperand &mo = mi.getOperand(1);
        const MachineOperand &mc = mi.getOperand(2);
        if (mo.isReg() && mo.getReg() == ARM::R11 && mc.isImm()) {

          // TODO: Need to check the imm is larger than 0 and it is align
          // by 4(32 bit).
          int imm = mc.getImm();
          if (imm >= 0) {

            // The start index of arguments on stack. If the library was
            // compiled by clang, it starts from 2. If the library was compiled
            // by GNU cross compiler, it starts from 1.
            // FIXME: For now, we only treat that the library was complied by
            // clang. We will enable the 'if condition' after we are able to
            // identify the library was compiled by which compiler.
            int idxoff = 2;
            if (true /* clang */)
              idxoff = 2;
            else /* gnu */
              idxoff = 1;

            int idx = imm / 4 - idxoff + 4; // Plus 4 is to guarantee the first
                                            // stack argument index is after all
                                            // of register arguments' indices.
            if (maxidx < idx)
              maxidx = idx;
            tarr[idx] = Type::getInt32Ty(ctx);
          }
        }
      }
    }
  }

  for (int i = 0; i <= maxidx; ++i) {
    if (tarr[i] == nullptr)
      paramTypes.push_back(Type::getInt32Ty(ctx));
    else
      paramTypes.push_back(tarr[i]);
  }
}

/// Get all arguments types of current MachineFunction.
bool ARMFunctionPrototype::isDefinedRegiser(unsigned reg,
                                            const MachineBasicBlock &mbb) {

  for (MachineBasicBlock::const_reverse_iterator ii = mbb.rbegin(),
                                                 ie = mbb.rend();
       ii != ie; ++ii) {
    const MachineInstr &mi = *ii;
    for (MachineInstr::const_mop_iterator oi = mi.operands_begin(),
                                          oe = mi.operands_end();
         oi != oe; oi++) {
      const MachineOperand &mo = *oi;
      if (mo.isReg() && (mo.getReg() == reg)) {
        // The return register must not be tied to another register.
        // If it was, it should not be return register.
        if (mo.isTied())
          return false;

        return mo.isDef();
      }
    }
  }

  return false;
}

/// Get return type of current MachineFunction.
Type *ARMFunctionPrototype::genReturnType(const MachineFunction &mf,
                                          LLVMContext &ctx) {
  // TODO: Need to track register liveness on CFG.
  Type *retTy;

  retTy = Type::getVoidTy(ctx);
  for (const MachineBasicBlock &mbb : mf) {
    if (mbb.succ_empty()) {
      if (isDefinedRegiser(ARM::R0, mbb)) {
        // TODO: Need to identify data type, int, long, float or double.
        retTy = Type::getInt32Ty(ctx);
        break;
      }
    }
  }

  return retTy;
}

Function *ARMFunctionPrototype::discover(MachineFunction &mf) {
  if (PrintPass)
    dbgs() << "ARMFunctionPrototype start.\n";

  Function &fn = const_cast<Function &>(mf.getFunction());
  LLVMContext &ctx = fn.getContext();

  std::vector<Type *> paramTys;
  genParameterTypes(paramTys, mf, ctx);
  Type *retTy = genReturnType(mf, ctx);
  FunctionType *fnTy = FunctionType::get(retTy, paramTys, false);

  MachineModuleInfo &mmi = mf.getMMI();
  Module *mdl = const_cast<Module *>(mmi.getModule());
  mdl->getFunctionList().remove(&fn);
  Function *pnfn =
      Function::Create(fnTy, GlobalValue::ExternalLinkage, fn.getName(), mdl);

  if (PrintPass) {
    mf.dump();
    pnfn->dump();
  }

  if (PrintPass)
    dbgs() << "ARMFunctionPrototype end.\n";

  return pnfn;
}

bool ARMFunctionPrototype::runOnMachineFunction(MachineFunction &mf) {
  discover(mf);
  return true;
}

#ifdef __cplusplus
extern "C" {
#endif
MachineFunctionPass *InitializeARMFunctionPrototype() {
  return new ARMFunctionPrototype();
}
#ifdef __cplusplus
}
#endif
