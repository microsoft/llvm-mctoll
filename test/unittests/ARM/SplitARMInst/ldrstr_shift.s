# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLi $r1, 2
# CHECK-NEXT: %1:gprnopc = ADDrr $r0, %0:gprnopc
# CHECK-NEXT: STRi12 $r0, %1:gprnopc
# CHECK-NEXT: %2:gprnopc = LSLi $r1, 2
# CHECK-NEXT: %3:gprnopc = ADDrr $r0, %2:gprnopc
# CHECK-NEXT: LDRi12 %stack.0, %3:gprnopc
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLi $r1, 2, 0, $cpsr
# CHECK-NEXT: %1:gprnopc = ADDrr $r0, %0:gprnopc, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, %1:gprnopc, 0, $cpsr
# CHECK-NEXT: %2:gprnopc = LSLi $r1, 2, 0, $cpsr
# CHECK-NEXT: %3:gprnopc = ADDrr $r0, %2:gprnopc, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 %3:gprnopc, 0, $cpsr
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: %1:gprnopc = ADDrr $r0, %0:gprnopc
# CHECK-NEXT: STRi12 $r0, %1:gprnopc
# CHECK-NEXT: %2:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: %3:gprnopc = ADDrr $r0, %2:gprnopc
# CHECK-NEXT: LDRi12 %stack.0, %3:gprnopc
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: %1:gprnopc = ADDrr $r0, %0:gprnopc, 0, $cpsr
# CHECK-NEXT: STRi12 $r0, %1:gprnopc, 0, $cpsr
# CHECK-NEXT: %2:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: %3:gprnopc = ADDrr $r0, %2:gprnopc, 0, $cpsr
# CHECK-NEXT: $r0 = LDRi12 %3:gprnopc, 0, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLDRSTRShf
  .type funcLDRSTRShf, %function
funcLDRSTRShf:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  str r0, [r0, r1, lsl #2]
  ldr r0, [r0, r1, lsl #2]
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLDRSTRShf, .-funcLDRSTRShf

  .global funcLDRSTRShfC
  .type funcLDRSTRShfC, %function
funcLDRSTRShfC:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  streq r0, [r0, r1, lsl #2]
  ldreq r0, [r0, r1, lsl #2]
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
   mov	r2, r1
   mov	r3, r0
   str	r0, [sp, #12]
   str	r1, [sp, #8]
   ldr	r0, [sp, #12]
   ldr	r1, [sp, #8]
   str  r0, [r0, r1, rrx]
   ldr  r0, [r0, r1, rrx]
   str	r2, [sp, #4]
   str	r3, [sp]
   add	sp, sp, #16
   bx	lr
   .size funcLDRSTRShfRRX, .-funcLDRSTRShfRRX

   .global funcLDRSTRShfRRXC
   .type funcLDRSTRShfRRXC, %function
 funcLDRSTRShfRRXC:
   sub	sp, sp, #16
   mov	r2, r1
   mov	r3, r0
   str	r0, [sp, #12]
   str	r1, [sp, #8]
   ldr	r0, [sp, #12]
   ldr	r1, [sp, #8]
   streq r0, [r0, r1, rrx]
   ldreq r0, [r0, r1, rrx]
   add r0, r0, r1
   str	r2, [sp, #4]
   str	r3, [sp]
   add	sp, sp, #16
   bx	lr
   .size funcLDRSTRShfRRXC, .-funcLDRSTRShfRRXC
