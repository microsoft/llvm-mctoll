#include "MachineFunctionRaiser.h"
#include "RISCV64ModuleRaiser.h"
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
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

// NOTE : The following RISCV64ModuleRaiser class function is defined here as
// they reference MachineFunctionRaiser class that has a forward declaration
// in ModuleRaiser.h.

// Create a new MachineFunctionRaiser object and add it to the list of
// MachineFunction raiser objects of this module.
MachineFunctionRaiser *RISCV64ModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *F, const ModuleRaiser *MR, uint64_t Start, uint64_t End) {
  MachineFunctionRaiser *MFR = new MachineFunctionRaiser(
      *M, MR->getMachineModuleInfo()->getOrCreateMachineFunction(*F), MR, Start,
      End);

  // TODO: Once we create a RISCVMachineInstructionRaiser add it here
  /*
  MFR->setMachineInstrRaiser(new X86MachineInstructionRaiser(
      MFR->getMachineFunction(), MR, MFR->getMCInstRaiser()));
  */

  mfRaiserVector.push_back(MFR);
  return MFR;
}
