// REQUIRES: system-linux
// Test code generated using default system linker (typically ld)
// RUN: clang -o %t-ld-opt %s -O2 -mno-sse -fuse-ld=ld
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-ld-opt
// RUN: clang -o %t-ld-opt-dis %t-ld-opt-dis.ll
// RUN: %t-ld-opt-dis 2>&1 | FileCheck %s -check-prefix=CHECK-LD
// CHECK-LD: Array[0]: 3
// CHECK-LD: Array[4]: 3
// CHECK-LD: Array[8]: 3
// CHECK-LD: Array[12]: 3
// CHECK-EMPTY

// Test code generated using lld linker
// RUN: clang -o %t-lld-opt %s -O2 -mno-sse -fuse-ld=lld
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-lld-opt
// RUN: clang -o %t-lld-opt-dis %t-lld-opt-dis.ll
// RUN: %t-lld-opt-dis 2>&1 | FileCheck %s -check-prefix=CHECK-LLD
// CHECK-LLD: Array[0]: 3
// CHECK-LLD: Array[4]: 3
// CHECK-LLD: Array[8]: 3
// CHECK-LLD: Array[12]: 3
// CHECK-EMPTY

/* matrix_loop() will check the instructon of LEA64_32 which miss the add
 * instruction. The insturction such as $edx = LEA64_32r $r8, 1, $rsi, 0, $noreg
 * matrix_loop will check CMP64rr, SUB64rr and X86::COND_AE.
 */

#include <stdio.h>
typedef signed short MATDAT;
typedef unsigned int ee_u32;
MATDAT A[16];

void __attribute__((noinline)) matrix_double_loop(ee_u32 N) {
  for (ee_u32 i = 0; i < N; i++) {
    for (ee_u32 j = 0; j < N; j++) {
      A[i * N + j] = 3;
    }
  }
}

int main() {
  ee_u32 N = 4;
  matrix_double_loop(N);
  for (ee_u32 i = 0; i < N; i++) {
    printf("Array[%d]: %d \n", i * N, A[i * N]);
  }
  return 0;
}
