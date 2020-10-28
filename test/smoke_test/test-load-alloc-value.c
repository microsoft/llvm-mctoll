// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: C[0]: 0
// CHECK: C[1]: 2
// CHECK: C[2]: 4
// CHECK: C[3]: 6
// CHECK: C[4]: 8
// CHECK: C[5]: 10
// CHECK: C[6]: 12
// CHECK: C[7]: 14
// CHECK: C[8]: 16
// CHECK: C[9]: 18
// CHECK: C[10]: 20
// CHECK: C[11]: 22
// CHECK: C[12]: 24
// CHECK: C[13]: 26
// CHECK: C[14]: 28
// CHECK: C[15]: 30

/*
 * Code will poduce MI as follows:
 * $ecx = LEA64_32r $rbp, 1, $noreg, -3, $noreg, <0x5573d216a278>
 */

#include <stdio.h>

signed short A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
signed int C[16] = {0};

void call_func(unsigned int N, signed int *C, signed short *A,
                      signed short val) {
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      C[i * N + j] = (signed int)A[i * N + j] * (signed int)val;
    }
  }
}

void foo(unsigned int N, signed int *C, signed short *A,
                         signed short val) {
  call_func(N, C, A, val);
  for (unsigned int i = 0; i < N; i++) {
    for (unsigned int j = 0; j < N; j++) {
      printf("C[%d]: %d \n", i * N + j, C[i * N + j]);
    }
  }
}

int main() {
  unsigned int N = 4;
  short val = 2;
  foo(N, C, A, val);
  return 0;
}
