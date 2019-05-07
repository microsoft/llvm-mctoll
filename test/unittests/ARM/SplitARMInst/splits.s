# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = ASRi $r0, 2
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc, 14, $cpsr
# CHECK-NEXT: %1:gprnopc = ASRi $r0, 2, 14, $cpsr
# CHECK-NEXT: $r0 = EORrr $r1, %1:gprnopc, 14, $cpsr
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcSplitS
  .type funcSplitS, %function
funcSplitS:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  adds	r0, r1, r0, asr #2
  eors	r0, r1, r0, asr #2
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcSplitS, .-funcSplitS
