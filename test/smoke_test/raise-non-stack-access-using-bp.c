// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: B[0]: 0
// CHECK: B[1]: 2
// CHECK: B[2]: 4
// CHECK: B[3]: 6
// CHECK: B[4]: 8
// CHECK: B[5]: 10
// CHECK: B[6]: 12
// CHECK: B[7]: 14
// CHECK: B[8]: 16
// CHECK: B[9]: 18
// CHECK: B[10]: 20
// CHECK: B[11]: 22
// CHECK: B[12]: 24
// CHECK: B[13]: 26
// CHECK: B[14]: 28
// CHECK: B[15]: 30

/*
 * Compiled code of foo() contains code that accesses non-stack memory but via
 * RBP, such as
 *              movzx eax,WORD PTR [rbp+rbp*1+0x601030]
 * where 0x601030 is the address of the global array A.
 */

#include <stdio.h>

signed short A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
signed short B[16] = {0};

void __attribute__((noinline)) foo(unsigned int N, short *B, short val) {
  unsigned int i = 0, j = 0;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      B[i * N + j] = A[i * N + j] * val;
    }
  }
}

int main() {
  unsigned int N = 4;
  short val = 2;
  foo(N, B, val);

  for (unsigned int i = 0; i < N; i++) {
    for (unsigned int j = 0; j < N; j++) {
      printf("B[%d]: %d \n", i * N + j, B[i * N + j]);
    }
  }
  return 0;
}
