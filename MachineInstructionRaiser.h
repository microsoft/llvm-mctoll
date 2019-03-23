//===-- MachineInstructionRaiser.h - Binary raiser utility llvm-mctoll ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of MachineInstructionRaiser class used
// by llvm-mctoll. This class encapsulates the raising of MachineInstruction
// to LLVM Instruction
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H

#include "MCInstRaiser.h"
#include "ModuleRaiser.h"
#include "llvm/CodeGen/MachineFunction.h"

using namespace llvm;

// Structure holding all necessary information to raise control
// transfer (i.e., branch) instructions during a post-processing
// phase.

typedef struct {
  BasicBlock *CandidateBlock;
  // This is the MachineInstr that needs to be raised
  const MachineInstr *CandidateMachineInstr;
  // A vector of values that could be of use while raising
  // CandidateMachineInstr. If it is a call instruction,
  // This vector has the Values corresponding to argument
  // registers (TODO : need to handles arguments passed on stack)
  std::vector<Value *> RegValues;
  // Flag to indicate that CandidateMachineInstr has been raised
  bool Raised;
} ControlTransferInfo;

class MachineInstructionRaiser {
public:
  MachineInstructionRaiser() = delete;
  MachineInstructionRaiser(MachineFunction &machFunc, const ModuleRaiser *mr,
                           MCInstRaiser *mcir = nullptr)
      : MF(machFunc), raisedFunction(nullptr), mcInstRaiser(mcir), MR(mr),
        PrintPass(false) {}
  virtual ~MachineInstructionRaiser(){};

  virtual bool raise() { return true; };
  virtual FunctionType *getRaisedFunctionPrototype() = 0;
  virtual int getArgumentNumber(unsigned PReg) = 0;
  virtual Value *getRegOrArgValue(unsigned PReg, int MBBNo) = 0;
  virtual bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                                      std::vector<Type *> &) = 0;

  Function *getRaisedFunction() { return raisedFunction; }
  MCInstRaiser *getMCInstRaiser() { return mcInstRaiser; }
  MachineFunction &getMF() { return MF; };
  const ModuleRaiser *getModuleRaiser() { return MR; }

  std::vector<ControlTransferInfo *> getControlTransferInfo() {
    return CTInfo;
  };

protected:
  MachineFunction &MF;
  // This is the Function object that holds the raised abstraction of MF.
  // Not the the function associated with MF should not be referenced or
  // updated. It was created just to enable the creation of MF.
  Function *raisedFunction;
  MCInstRaiser *mcInstRaiser;
  const ModuleRaiser *MR;

  // A vector of information to be used for raising of control transfer
  // (i.e., Call and Terminator) instructions.
  std::vector<ControlTransferInfo *> CTInfo;

  bool PrintPass;
};
#endif // LLVM_TOOLS_LLVM_MCTOLL_MACHINEINSTRUCTIONRAISER_H
