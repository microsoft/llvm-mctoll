// RUN: clang %s -o %t --target=%arm_triple
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Short result: 5

#include <stdio.h>

short func(short a1, short a2) {
  short c1, c2;
  c1 = 2;
  c2 = a1 + a2;

  return c1 + c2;
}

int main() {
  printf("Short result: %d\n", func(1, 2));
  return 0;
}
