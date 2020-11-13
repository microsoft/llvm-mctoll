# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: $r2 = ADDrr $r2, $r1
# CHECK-NEXT: STRi12 $r0, $r2
# CHECK-NEXT: $r3 = ADDrr $r3, $r1
# CHECK-NEXT: $r0 = LDRi12 $r3
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: $r2 = ADDrr $r2, $r1, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, $r2, 0, $cpsr
# CHECK-NEXT: $r3 = ADDrr $r3, $r1, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 $r3, 0, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLDRSTRRegPre
  .type funcLDRSTRRegPre, %function
funcLDRSTRRegPre:
  sub       sp, sp, #16
  mov       r2, r0
  mov       r3, r0
  str       r0, [sp, #12]
  str       r1, [sp, #8]
  ldr       r0, [sp, #12]
  ldr       r1, [sp, #8]
  str       r0, [r2, r1]!
  ldr       r0, [r3, r1]!
  str       r2, [sp, #4]
  str       r3, [sp]
  add       sp, sp, #16
  bx        lr
  .size funcLDRSTRRegPre, .-funcLDRSTRRegPre

  .global funcLDRSTRRegPreC
  .type funcLDRSTRRegPreC, %function
funcLDRSTRRegPreC:
  sub       sp, sp, #16
  mov       r2, r0
  mov       r3, r0
  str       r0, [sp, #12]
  str       r1, [sp, #8]
  ldr       r0, [sp, #12]
  ldr       r1, [sp, #8]
  streq     r0, [r2, r1]!
  ldreq     r0, [r3, r1]!
  add       r0, r0, r1
  str       r2, [sp, #4]
  str       r3, [sp]
  add       sp, sp, #16
  bx        lr
  .size funcLDRSTRRegPreC, .-funcLDRSTRRegPreC
