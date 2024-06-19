//===-- ARMEliminatePrologEpilog.cpp ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMMachineInstructionRaiser class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMArgumentRaiser.h"
#include "ARMCreateJumpTable.h"
#include "ARMEliminatePrologEpilog.h"
#include "ARMFrameBuilder.h"
#include "ARMFunctionPrototype.h"
#include "ARMInstructionSplitting.h"
#include "ARMMIRevising.h"
#include "ARMMachineInstructionRaiser.h"
#include "ARMModuleRaiser.h"
#include "ARMSelectionDAGISel.h"

using namespace llvm;
using namespace llvm::mctoll;

ARMMachineInstructionRaiser::ARMMachineInstructionRaiser(
    MachineFunction &MF, const ModuleRaiser *MR, MCInstRaiser *MCIR)
    : MachineInstructionRaiser(MF, MR, MCIR), MachineRegInfo(MF.getRegInfo()) {}

bool ARMMachineInstructionRaiser::raise() {
  const ARMModuleRaiser *ConstAMR = dyn_cast<ARMModuleRaiser>(MR);
  assert(ConstAMR != nullptr && "The ARM module raiser is not initialized!");
  ARMModuleRaiser &AMR = const_cast<ARMModuleRaiser &>(*ConstAMR);

  ARMMIRevising MIR(AMR,&MF, RaisedFunction, InstRaiser);
  MIR.revise();

  ARMEliminatePrologEpilog EPE(AMR, &MF, RaisedFunction);
  EPE.eliminate();

  ARMCreateJumpTable CJT(AMR, &MF, RaisedFunction, InstRaiser);
  CJT.create();
  CJT.getJTlist(JTList);

  ARMArgumentRaiser AR(AMR, &MF, RaisedFunction);
  AR.raiseArgs();

  ARMFrameBuilder FB(AMR, &MF, RaisedFunction);
  FB.build();

  ARMInstructionSplitting ISpl(AMR, &MF, RaisedFunction);
  ISpl.split();

  ARMSelectionDAGISel SelDis(AMR, &MF, RaisedFunction);
  SelDis.setjtList(JTList);
  SelDis.doSelection();

  return true;
}

int ARMMachineInstructionRaiser::getArgumentNumber(unsigned PReg) {
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

Value *ARMMachineInstructionRaiser::getRegOrArgValue(unsigned PReg, int MBBNo) {
  assert(false &&
         "Unimplemented ARMMachineInstructionRaiser::getRegOrArgValue()");
  return nullptr;
}

FunctionType *ARMMachineInstructionRaiser::getRaisedFunctionPrototype() {
  ARMFunctionPrototype AFP;
  RaisedFunction = AFP.discover(MF);

  Function *Ori = const_cast<Function *>(&MF.getFunction());
  // Insert the map of raised function to tempFunctionPointer.
  const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
      RaisedFunction, Ori);

  return RaisedFunction->getFunctionType();
}

/// Create a new MachineFunctionRaiser object and add it to the list of
/// MachineFunction raiser objects of this module.
MachineFunctionRaiser *ARMModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *F, const ModuleRaiser *MR, uint64_t Start, uint64_t End) {
  MachineFunctionRaiser *MFR = new MachineFunctionRaiser(
      *M, MR->getMachineModuleInfo()->getOrCreateMachineFunction(*F), MR, Start,
      End);
  MFR->setMachineInstrRaiser(new ARMMachineInstructionRaiser(
      MFR->getMachineFunction(), MR, MFR->getMCInstRaiser()));
  MFRaiserVector.push_back(MFR);
  return MFR;
}
