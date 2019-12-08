// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s

// CHECK:C[0]: 8
// CHECK:C[1]: 8
// CHECK:C[2]: 8
// CHECK:C[3]: 8

/* foo() will produce machine instruction as follow:
 * $ecx = MOV32ri 6295632
 */

#include <stdio.h>

short A[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
short B[4] = {2, 2, 2, 2};
short C[4] = {0, 0, 0, 0};

void __attribute__((noinline)) foo(int N, short *C, short *A, short *B) {
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    C[i] = 0;
    for (j = 0; j < N; j++) {
      C[i] += A[i * N + j] * B[j];
    }
  }
}

int main() {
  int N = 4;
  foo(N, C, A, B);

  for (unsigned int i = 0; i < N; i++) {
    printf(" C[%d]: %d \n", i, C[i]);
  }
  return 0;
}
