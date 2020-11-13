# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = ASRi $r0, 2
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = ASRi $r0, 2
# CHECK-NEXT: $r0 = MOVr %1:gprnopc
# CHECK: ARMInstructionSplitting end

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = ASRr $r0, $r1
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = ASRr $r0, $r1
# CHECK-NEXT: $r0 = MOVr %1:gprnopc
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcASRImm
  .type funcASRImm, %function
funcASRImm:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, asr #2
  mov r0, r0, asr #2
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcASRImm, .-funcASRImm

  .global funcASRReg
  .type funcASRReg, %function
funcASRReg:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, asr r1
  mov	r0, r0, asr r1
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcASRReg, .-funcASRReg
