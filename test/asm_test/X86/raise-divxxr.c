// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: [Implicit AH/AL]
// CHECK-NEXT: Test 0xfffffffa IDIV8r 0xfffffff0
// CHECK-NEXT: Quotient = 0xfffffff1, Remainder = 0xa
// CHECK-EMPTY
#include <stdio.h>

// IDIVr8
int __attribute__((noinline))
test_idiv8r(char a, char b) {
  char quotient = 0;
  char remainder = 0;

  printf("[Implicit AH/AL]\nTest 0x%x IDIV8r 0x%x\n", a, b);

  asm("movzbw  %2, %%ax\n"
      "idivb  %3\n"
      "mov  %%ah, %1\n"
      "mov  %%al, %0\n"
      : "=r"(quotient), "=r"(remainder)      /* output operands */
      : "r"(a), "r"(b)                       /* input operands */
      : "%ax"                                /* list of clobbered registers */
  );

  printf("Quotient = 0x%x, Remainder = 0x%x\n", quotient, remainder);
  return 0;
}

int main() {
  test_idiv8r(0xFA, 0xF0);
  return 0;
}
