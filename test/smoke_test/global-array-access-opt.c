// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: Array[4]: 7
// CHECK: Array[0]: 6
// CHECK: Array[4]: 6
// CHECK: Array[8]: 6
// CHECK: Array[12]: 6

/* This tests correct handling of full memory address operands such as
 * [rax+rax*1+0x601040], where the displacement is (0x601040, in this example)
 * is a global aggregate - such as an array. Such code, is typically generated
 * optimized code is generated.
 * matrix_loop() will check the instructon of LEA64_32 which miss the add instruction.
 * The insturction such as $edx = LEA64_32r $r8, 1, $rsi, 0, $noreg
 * matrix_loop will check CMP64rr, SUB64rr and X86::COND_AE.
 */

#include <stdio.h>
typedef signed short MATDAT;
typedef unsigned int ee_u32;
MATDAT A[16];
void __attribute__((noinline)) matrix_init(ee_u32 N) {
  A[N] = 7;
  return;
}

void __attribute__((noinline)) matrix_loop(ee_u32 N) {
  for (ee_u32 i = 0; i < N; i++) {
    A[i * N] = 6;
  }
  return;
}

int main() {
  ee_u32 N = 4;
  matrix_init(N);
  printf("Array[4]: %d \n", A[4]);

  matrix_loop(N);
  for (ee_u32 i = 0; i < N; i++) {
    printf("Array[%d]: %d \n", i * N, A[i * N]);
  }
  return 0;
}
