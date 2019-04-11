# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMInstructionSplitting start
# CHECK: %0:gprnopc = RRX $r0, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: $r0 = ADDrr $r1, %0:gprnopc
# CHECK-NEXT: %1:gprnopc = RRX $r1, <{{0x[0-9a-f]+}}>, implicit $cpsr
# CHECK-NEXT: MOVr %stack.0, %1:gprnopc
# CHECK: ARMInstructionSplitting end

  .text
  .align 4
  .code 32
  .global funcRRX
  .type funcRRX, %function
funcRRX:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r1, r0, rrx
  mov r0, r1, rrx
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size funcRRX, .-funcRRX
