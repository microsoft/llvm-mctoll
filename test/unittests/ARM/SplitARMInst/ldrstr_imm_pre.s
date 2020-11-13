# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: $r1 = ADDrr $r1, 4
# CHECK-NEXT: STRi12 $r0, $r1
# CHECK-NEXT: $r1 = SUBri $r1, 4, 14
# CHECK-NEXT: $r1 = ADDrr $r1, 4
# CHECK-NEXT: $r0 = LDRi12 $r1
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: $r1 = ADDrr $r1, 4, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, $r1, 0, $cpsr
# CHECK-NEXT: $r1 = SUBri $r1, 4, 0, $cpsr
# CHECK-NEXT: $r1 = ADDrr $r1, 4, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 $r1, 0, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLDRSTRImmPre
  .type funcLDRSTRImmPre, %function
funcLDRSTRImmPre:
  sub       sp, sp, #16
  mov       r2, r1
  mov       r3, r0
  str       r0, [sp, #12]
  str       r1, [sp, #8]
  ldr       r0, [sp, #12]
  ldr       r1, [sp, #8]
  str       r0, [r1, #4]!
  sub       r1, r1, #4
  ldr       r0, [r1, #4]!
  str       r2, [sp, #4]
  str       r3, [sp]
  add       sp, sp, #16
  bx        lr
  .size funcLDRSTRImmPre, .-funcLDRSTRImmPre

  .global funcLDRSTRImmPreC
  .type funcLDRSTRImmPreC, %function
funcLDRSTRImmPreC:
  sub       sp, sp, #16
  mov       r2, r1
  mov       r3, r0
  str       r0, [sp, #12]
  str       r1, [sp, #8]
  ldr       r0, [sp, #12]
  ldr       r1, [sp, #8]
  streq     r0, [r1, #4]!
  subeq     r1, r1, #4
  ldreq     r0, [r1, #4]!
  add       r0, r0, r1
  str       r2, [sp, #4]
  str       r3, [sp]
  add       sp, sp, #16
  bx        lr
  .size funcLDRSTRImmPreC, .-funcLDRSTRImmPreC
