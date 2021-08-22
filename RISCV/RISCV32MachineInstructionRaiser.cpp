#include "IncludedFileInfo.h"
#include "MachineFunctionRaiser.h"
#include "RISCV32ModuleRaiser.h"
#include "llvm-mctoll.h"

// NOTE : The following RISCV32ModuleRaiser class function is defined here as
// they reference MachineFunctionRaiser class that has a forward declaration
// in ModuleRaiser.h.

// Create a new MachineFunctionRaiser object and add it to the list of
// MachineFunction raiser objects of this module.
MachineFunctionRaiser *RISCV32ModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *F, const ModuleRaiser *MR, uint64_t Start, uint64_t End) {
  MachineFunctionRaiser *MFR = new MachineFunctionRaiser(
      *M, MR->getMachineModuleInfo()->getOrCreateMachineFunction(*F), MR, Start,
      End);

  //TODO: Need to create RISCV32MachineInstrucitionRaiser
  //MFR->setMachineInstrRaiser(new X86MachineInstructionRaiser(
  //  MFR->getMachineFunction(), MR, MFR->getMCInstRaiser()));

  mfRaiserVector.push_back(MFR);
  return MFR;
}
