// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: x = 0x02

#include <limits.h> // for CHAR_BIT
#include <stdio.h>

__attribute__((noinline)) void setbit(char *set, int index, int value) {
  set += index / CHAR_BIT;
  if (value)
    *set |= 1 << (index % CHAR_BIT); /* set bit  */
  else
    *set &= ~(1 << (index % CHAR_BIT)); /* clear bit*/
}

int main() {
  char x = 0;
  setbit(&x, 1, 1);
  printf("x = 0x%02x\n", (int)x);
  return 0;
}
