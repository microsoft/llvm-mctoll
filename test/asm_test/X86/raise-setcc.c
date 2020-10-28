// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Test SETCC_LE_GE 5 + 6
// CHECK: Result : 11 LE = 0 GE = 1

/*
 * Test correctness of raising setle and setge instructions.
 *
 */

#include "stdint.h"
#include "stdio.h"

uint8_t __attribute__((noinline)) test_SETCC_LE_GE(uint8_t val, uint8_t val1) {
  uint8_t result;
  uint8_t le = 0, ge = 0;
  printf("Test SETCC_LE_GE %d + %d\n", val, val1);
  __asm__("mov %3, %%al \n"
          "mov %4, %%bl \n"
          "add %%al, %%bl \n"
          "setle %%cl\n"
          "setge %%dl\n"
          "mov %%bl, %0 \n"
          "mov %%cl, %1\n"
          "mov %%dl, %2\n"
          : "=r"(result), "=r"(le), "=r"(ge) /* output */
          : "r"(val), "r"(val1)              /* input */
          : "%al", "%bl", "%cl", "%dl"       /* clobbered register */
  );
  printf("Result : %hd LE = %hd GE = %hd\n", result, le, ge);
  return result;
}

int main() {
  uint8_t res = test_SETCC_LE_GE(5, 6);
  return 0;
}
