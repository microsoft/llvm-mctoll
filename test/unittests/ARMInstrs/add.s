  .text
  .align 4
  .code 32
  .global funcAddReg
  .type funcAddReg, %function
funcAddReg:
  sub	sp, sp, #16
  mov	r2, r1
  mov	r3, r0
  str	r0, [sp, #12]
  str	r1, [sp, #8]
  ldr	r0, [sp, #12]
  ldr	r1, [sp, #8]
  add	r0, r0, r1
  str	r2, [sp, #4]
  str	r3, [sp]
  add	sp, sp, #16
  bx	lr
  .size    funcAddReg, .-funcAddReg
