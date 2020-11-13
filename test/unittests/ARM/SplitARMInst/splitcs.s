# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = ASRi $r0, 2, 0, $cpsr
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc, 0, $cpsr, $cpsr
# CHECK-NEXT: %1:gprnopc = ASRi $r0, 2, 0, $cpsr, $cpsr
# CHECK-NEXT: $r0 = EORrr $r1, %1:gprnopc, 0, $cpsr, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcSplitCS
  .type funcSplitCS, %function
funcSplitCS:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  addseq	r0, r1, r0, asr #2
  eorseq	r0, r1, r0, asr #2
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcSplitCS, .-funcSplitCS
