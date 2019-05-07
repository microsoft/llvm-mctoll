// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: Array[4]: 7

/* This tests correct handling of full memory address operands such as
 * [rax+rax*1+0x601040], where the displacement is (0x601040, in this example)
 * is a global aggregate - such as an array. Such code, is typically generated
 * optimized code is generated.
 */

#include <stdio.h>
typedef signed short MATDAT;
typedef unsigned int ee_u32;
MATDAT A[16];
void __attribute__((noinline)) matrix_init(ee_u32 N) {
  A[N] = 7;
  return;
}

int main() {
  ee_u32 N = 4;
  matrix_init(N);
  printf("Array[4]: %d \n", A[4]);
  return 0;
}
