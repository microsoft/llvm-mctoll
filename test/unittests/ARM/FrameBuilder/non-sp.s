# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug -print-after-all %t.o 2>&1 | FileCheck %s
# CHECK: ARMFrameBuilder start
# CHECK: %stack.3.stack.3
# CHECK: %stack.4.stack.4
# CHECK: %stack.5.stack.5
# CHECK: %stack.6.stack.6
# CHECK: ARMFrameBuilder end

  .text
  .align 4
  .code 32
  .global funcNonSP
  .type funcNonSP, %function
funcNonSP:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  mov   r5, sp
  str	r0, [r5, #12]
  str	r1, [r5, #8]
  ldr	r0, [r5, #12]
  ldr	r1, [r5, #8]
  str	r2, [r5, #4]
  str	r3, [r5]
  add	sp, sp, #16
  bx	lr
  .size funcNonSP, .-funcNonSP

