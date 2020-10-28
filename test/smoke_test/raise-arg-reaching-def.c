// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: B[0]: 0
// CHECK: B[4]: 8
// CHECK: B[8]: 16
// CHECK: B[12]: 24
// CHECK: result B[0]: 0
// CHECK: result B[1]: 2
// CHECK: result B[2]: 4
// CHECK: result B[3]: 6
// CHECK: result B[4]: 8
// CHECK: result B[5]: 10
// CHECK: result B[6]: 12
// CHECK: result B[7]: 14
// CHECK: result B[8]: 16
// CHECK: result B[9]: 18
// CHECK: result B[10]: 20
// CHECK: result B[11]: 22
// CHECK: result B[12]: 24
// CHECK: result B[13]: 26
// CHECK: result B[14]: 28
// CHECK: result B[15]: 30

/* call_func() code raising involves a lookup of reaching definition of argument
   register in entry block.
 */

#include <stdio.h>

signed short A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
signed short B[16] = {0};

void __attribute__((noinline)) call_func(unsigned int N, short *B, short val) {
  unsigned int i = 0, j = 0;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      B[i * N + j] = A[i * N + j] * val;
    }
    printf("B[%d]: %d \n", i * N, B[i * N]);
  }
}

int main() {
  unsigned int N = 4;
  short val = 2;
  call_func(N, B, val);
  for (unsigned int i = 0; i < N; i++) {
    for (unsigned int j = 0; j < N; j++) {
      printf("result B[%d]: %d \n", i * N + j, B[i * N + j]);
    }
  }
  return 0;
}
