# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLi $r0, 4
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = LSLi $r0, 2
# CHECK-NEXT: $r0 = MOVr %1:gprnopc
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = LSLr $r0, $r1
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = LSLr $r0, $r1
# CHECK-NEXT: $r0 = MOVr %1:gprnopc
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcLSLImm
  .type funcLSLImm, %function
funcLSLImm:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, lsl #4
  mov r0, r0, lsl #2
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLSLImm, .-funcLSLImm

  .global funcLSLReg
  .type funcLSLReg, %function
funcLSLReg:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, lsl r1
  mov r0, r0, lsl r1
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcLSLReg, .-funcLSLReg
