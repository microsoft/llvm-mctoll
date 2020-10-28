// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: IMUL32rri 0x98723 by 0xc7f57418
// CHECK-NEXT: Result : 0xdb9f8748 OF = 1 CF = 1
// CHECK-NEXT: IMUL32rri 0x1 by 0xc7f57418
// CHECK-NEXT: Result : 0xc7f57418 OF = 0 CF = 0
// CHECK-NEXT: IMUL16rri 0x9872 by 0xc7f5
// CHECK-NEXT: Result : 0x831a OF = 1 CF = 1
// CHECK-NEXT: IMUL16rri 0x1 by 0xc7f5
// CHECK-NEXT: Result : 0xc7f5 OF = 0 CF = 0
// CHECK-EMPTY
#include "stdint.h"
#include "stdio.h"

/* Test raising imul instruction.
   Also test the correctness of flags set by the ror instruction.
*/

// Compute imul reg16, reg16, imm16
uint16_t __attribute__((noinline)) signed_mul16_three_operand(uint16_t v1) {
  uint16_t result;
  uint8_t of = 0, cf = 0;
  printf("IMUL16rri 0x%x by 0xc7f5\n", v1);
  __asm__("mov %3, %%bx \n"
          "imul   %4, %%bx, %%ax\n"
          "setc %%cl\n"
          "seto %%dl\n"
          "mov %%ax, %0 \n"
          "mov %%cl, %1\n"
          "mov %%dl, %2\n"
          : "=r"(result), "=r"(cf), "=r"(of) /* output */
          : "r"(v1), "i"(0xc7f5)             /* input */
          : "%ax", "%bx", "%cx", "%dl"       /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute imul reg32, reg32, imm32
uint32_t __attribute__((noinline)) signed_mul32_three_operand(uint32_t v1) {
  uint32_t result;
  uint8_t of = 0, cf = 0;
  printf("IMUL32rri 0x%x by 0xc7f57418\n", v1);
  __asm__("mov %3, %%ebx \n"
          "imul   %4, %%ebx, %%eax\n"
          "setc %%cl\n"
          "seto %%dl\n"
          "mov %%eax, %0 \n"
          "mov %%cl, %1\n"
          "mov %%dl, %2\n"
          : "=r"(result), "=r"(cf), "=r"(of) /* output */
          : "r"(v1), "i"(0xc7f57418)         /* input */
          : "%eax", "%ebx", "%ecx", "%dl"    /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Test various flavors of imil
int main() {
  uint32_t r32 = signed_mul32_three_operand(0x98723);
  r32 = signed_mul32_three_operand(0x1);

  uint16_t r16 = signed_mul16_three_operand(0x9872);
  r16 = signed_mul16_three_operand(0x1);
  return 0;
}
