# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLi $r1, 2
# CHECK-NEXT: $r2 = ADDrr $r2, %0:gprnopc
# CHECK-NEXT: STRi12 $r0, $r2
# CHECK-NEXT: %1:gprnopc = LSLi $r1, 2
# CHECK-NEXT: $r3 = ADDrr $r3, %1:gprnopc
# CHECK-NEXT: $r0 = LDRi12 $r3
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLi $r1, 2, 0, $cpsr
# CHECK-NEXT: $r2 = ADDrr $r2, %0:gprnopc, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, $r2, 0, $cpsr
# CHECK-NEXT: %1:gprnopc = LSLi $r1, 2, 0, $cpsr
# CHECK-NEXT: $r3 = ADDrr $r3, %1:gprnopc, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 $r3, 0, $cpsr
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: $r2 = ADDrr $r2, %0:gprnopc
# CHECK-NEXT: STRi12 $r0, $r2
# CHECK-NEXT: %1:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: $r3 = ADDrr $r3, %1:gprnopc
# CHECK-NEXT: $r0 = LDRi12 $r3
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: $r2 = ADDrr $r2, %0:gprnopc, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, $r2, 0, $cpsr
# CHECK-NEXT: %1:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: $r3 = ADDrr $r3, %1:gprnopc, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 $r3, 0, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLDRSTRShf
  .type funcLDRSTRShf, %function
funcLDRSTRShf:
  sub	sp, sp, #16
  mov	r2, r0
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  str r0, [r2, r1, lsl #2]!
  ldr r0, [r3, r1, lsl #2]!
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLDRSTRShf, .-funcLDRSTRShf

  .global funcLDRSTRShfC
  .type funcLDRSTRShfC, %function
funcLDRSTRShfC:
  sub	sp, sp, #16
  mov	r2, r0
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  streq r0, [r2, r1, lsl #2]!
  ldreq r0, [r3, r1, lsl #2]!
  add r0, r0, r1
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLDRSTRShfC, .-funcLDRSTRShfC

  .global funcLDRSTRShfRRX
  .type funcLDRSTRShfRRX, %function
 funcLDRSTRShfRRX:
   sub	sp, sp, #16
   mov	r2, r0
   mov	r3, r0
   str	r0, [sp, #12]
   str	r1, [sp, #8]
   ldr	r0, [sp, #12]
   ldr	r1, [sp, #8]
   str  r0, [r2, r1, rrx]!
   ldr  r0, [r3, r1, rrx]!
   str	r2, [sp, #4]
   str	r3, [sp]
   add	sp, sp, #16
   bx	lr
   .size funcLDRSTRShfRRX, .-funcLDRSTRShfRRX

   .global funcLDRSTRShfRRXC
   .type funcLDRSTRShfRRXC, %function
 funcLDRSTRShfRRXC:
   sub	sp, sp, #16
   mov	r2, r0
   mov	r3, r0
   str	r0, [sp, #12]
   str	r1, [sp, #8]
   ldr	r0, [sp, #12]
   ldr	r1, [sp, #8]
   streq r0, [r2, r1, rrx]!
   ldreq r0, [r3, r1, rrx]!
   add r0, r0, r1
   str	r2, [sp, #4]
   str	r3, [sp]
   add	sp, sp, #16
   bx	lr
   .size funcLDRSTRShfRRXC, .-funcLDRSTRShfRRXC
