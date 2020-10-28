// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:matrix_mul_const B[0]: 0
// CHECK:matrix_mul_const B[4]: 20
// CHECK:matrix_mul_const B[8]: 40
// CHECK:matrix_mul_const B[12]: 60

/* matrix_mul_const() will produce machine instruction as follow:
 * $ax = IMUL16rr $ax(tied-def 0), $si, <0x561ecea3b1e8>,
 * implicit-def $eflags
 *
 * $si = IMUL16rm $si(tied-def 0), $rip, 1, $noreg, 2099862, $noreg,
 * <0x561ecea423a8>, implicit-def $eflags
 */

#include <stdio.h>

short A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
short B[16];
void __attribute__((noinline)) matrix_mul_const(short *B, short val) {
  unsigned int i = 0, j = 0;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      B[i * 4 + j] = A[i * 4 + j] * val;
    }
  }
}

int main() {

  int N = 4;
  short val = 5;
  matrix_mul_const(B, val);
  for (unsigned int i = 0; i < N; i++) {
    printf("matrix_mul_const B[%d]: %d \n", i * N, B[i * N]);
  }
  return 0;
}
