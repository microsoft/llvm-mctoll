// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0 % 2 = 0
// CHECK: 1 % 2 = 1
// CHECK: 2 % 2 = 0
// CHECK: 3 % 2 = 1
// CHECK: 4 % 2 = 0
// CHECK: 5 % 2 = 1
// CHECK: 6 % 2 = 0
// CHECK: 7 % 2 = 1
// CHECK: 8 % 2 = 0
// CHECK: 9 % 2 = 1
// CHECK-EMPTY

#include <stdio.h>

void mod(int n) {
  // the remainder of the division n / 2 will be saved in edx, which is the register
  // where it should be for the printf call
  // This test checks that mctoll recognizes that the sdiv instruction will
  // implicitly set edx
  printf("%d %% 2 = %d\n", n, n % 2);
}

int main(void) {
  for (int i = 0; i < 10; ++i) {
    mod(i);
  }
  return 0;
}
