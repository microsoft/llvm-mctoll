//===-- ARMEliminatePrologEpilog.cpp - Binary raiser utility llvm-mctoll --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMMachineInstructionRaiser class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "ARMEliminatePrologEpilog.h"
#include "ARMFunctionPrototype.h"

using namespace llvm;

ARMMachineInstructionRaiser::ARMMachineInstructionRaiser(
    MachineFunction &machFunc, const ModuleRaiser *mr, MCInstRaiser *mcir)
    : MachineInstructionRaiser(machFunc, mr, mcir),
      machRegInfo(MF.getRegInfo()) {}

bool ARMMachineInstructionRaiser::raiseMachineFunction() {
  ModuleRaiser &rmr = const_cast<ModuleRaiser &>(*MR);

  ARMEliminatePrologEpilog epe(rmr);
  epe.init(&MF, raisedFunction);
  epe.eliminate();

  return true;
}

bool ARMMachineInstructionRaiser::raise() {
  raiseMachineFunction();

  return true;
}

int ARMMachineInstructionRaiser::getArgumentNumber(unsigned int PReg) {
  // NYI
  assert(false &&
         "Unimplemented ARMMachineInstructionRaiser::getArgumentNumber()");
  return -1;
}

bool ARMMachineInstructionRaiser::buildFuncArgTypeVector(
    const std::set<MCPhysReg> &PhysRegs, std::vector<Type *> &ArgTyVec) {
  // NYI
  assert(false &&
         "Unimplemented ARMMachineInstructionRaiser::buildFuncArgTypeVector()");
  return false;
}

Value *ARMMachineInstructionRaiser::getRegValue(unsigned PReg) {
  assert(false && "Unimplemented ARMMachineInstructionRaiser::getRegValue()");
  return nullptr;
}

FunctionType *ARMMachineInstructionRaiser::getRaisedFunctionPrototype() {
  ARMFunctionPrototype AFP;
  raisedFunction = AFP.discover(MF);

  Function *ori = const_cast<Function *>(&MF.getFunction());
  // Insert the map of raised function to tempFunctionPointer.
  const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
      raisedFunction, ori);

  return raisedFunction->getFunctionType();
}

#ifdef __cplusplus
extern "C" {
#endif
MachineInstructionRaiser *
InitializeARMMachineInstructionRaiser(MachineFunction &machFunc, Module &m,
                                      const ModuleRaiser *mr,
                                      MCInstRaiser *mcir) {
  return new ARMMachineInstructionRaiser(machFunc, mr, mcir);
}
#ifdef __cplusplus
}
#endif
