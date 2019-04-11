# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSRi $r0, 2
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = LSRi $r0, 2
# CHECK-NEXT: MOVr %stack.0, %1:gprnopc
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSRr $r0, $r1
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = LSRr $r0, $r1
# CHECK-NEXT: MOVr %stack.0, %1:gprnopc
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLSRImm
  .type funcLSRImm, %function
funcLSRImm:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, lsr #2
  mov r0, r0, lsr #2
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLSRImm, .-funcLSRImm

  .global funcLSRReg
  .type funcLSRReg, %function
funcLSRReg:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, lsr r1
  mov r0, r0, lsr r1
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLSRReg, .-funcLSRReg
