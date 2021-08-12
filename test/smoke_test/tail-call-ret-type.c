// REQUIRES: system-linux
// RUN: clang -O3 -fno-inline -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 4^2 = 16
// CHECK-EMPTY

#include <stdio.h>

int mul(int x, int y) {
  return x * y;
}

int square(int x) {
  // this call should be compiled to a tail-call
  return mul(x, x);
}

void unused() {
  if (square(2) > 0) {
    printf("2^2 > 0\n");
  }
}

int main() {
  int val = 4;
  printf("%d^2 = %d\n", val, square(val));
  return 0;
}
