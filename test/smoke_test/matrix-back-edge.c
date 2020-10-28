// REQUIRES: system-linux
// RUN: clang -o %t %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: num: 0
// CHECK: num: 1
// CHECK: num: 2
// CHECK: num: 3
// CHECK: num: 1
// CHECK: num: 2
// CHECK: num: 3
// CHECK: num: 4
// CHECK: num: 2
// CHECK: num: 3
// CHECK: num: 4
// CHECK: num: 5
// CHECK: num: 3
// CHECK: num: 4
// CHECK: num: 5
// CHECK: num: 6

#include <stdio.h>

typedef unsigned int ee_u32;

int __attribute__((noinline)) matrix_init(ee_u32 N) {
  for (ee_u32 i = 0; i < N; i++) {
    for (ee_u32 j = 0; j < 4; j++) {
      printf("num: %d\n", i + j);
    }
  }
  return 0;
}

int main() {
  ee_u32 N = 4;
  matrix_init(N);
  return 0;
}
