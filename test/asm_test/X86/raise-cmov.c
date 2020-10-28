// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Test cmovno 0xbd
// CHECK-NEXT: Result : 0xdeadbeef
// CHECK-NEXT: Test cmovno 0x7fffffff
// CHECK-NEXT: Result : 0x80000001
// CHECK-NEXT: Test cmovo 0xbd
// CHECK-NEXT: Result : 0x800000be
// CHECK-NEXT: Test cmovo 0x80000000
// CHECK-NEXT: Result : 0xdeadbeef
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

/* Test raising cmovno and cmovo.
 */

// Return val+2 upon overflow; 0xdeadbeef otherwise
uint32_t __attribute__((noinline)) cmov_no(uint32_t val) {
  uint32_t result;
  printf("Test cmovno 0x%x\n", val);
  __asm__("mov %1, %%eax\n"
          "mov %2, %%ecx\n"
          "add $2, %%eax\n"
          "cmovno %%ecx, %%eax\n"
          "mov %%eax, %0\n"
          : "=r"(result)              /* output */
          : "r"(val), "i"(0xdeadbeef) /* input */
          : "%eax", "%ecx"            /* clobbered register */
  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Return val-2147483649 upon overflow; 0xdeadbeef otherwise
int32_t __attribute__((noinline)) cmov_o(int32_t val) {
  int32_t result;
  printf("Test cmovo 0x%x\n", val);
  __asm__("mov %1, %%eax\n"
          "mov %2, %%ecx\n"
          "sub %3, %%eax\n"
          "cmovo %%ecx, %%eax\n"
          "mov %%eax, %0\n"
          : "=r"(result)                                /* output */
          : "r"(val), "i"(0xdeadbeef), "i"(-2147483649) /* input */
          : "%eax", "%ecx"                              /* clobbered register */
  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Test raising of rotate instruction
int main() {
  // No overflow - output should be 0xdeadbeef
  uint8_t v = cmov_no(0xbd);
  // Triggers an overflow - output should be 0x80000001
  v = cmov_no(0x7fffffff);

  v = cmov_o(0xbd);
  v = cmov_o(-2147483648);

  return 0;
}
