// REQUIRES: system-linux
// RUN: clang -o %t %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: instr[0] = 72
// CHECK: instr[1] = 73
// CHECK: instr[2] = 74
// CHECK: instr[3] = 75
// CHECK: instr[4] = 76
// CHECK: instr[5] = 77
// CHECK: instr[6] = 78
// CHECK: instr[7] = 79
// CHECK: instr[8] = 80
// CHECK: instr[9] = 81

#include <stdio.h>
#include <stdlib.h>

typedef signed int ee_s32;
typedef unsigned int ee_u32;

void matrix_add_const(ee_u32 N, ee_s32 *A, ee_s32 val) {
  ee_u32 i, j;
  for (i = 0; i < N; i++) {
      A[i] += val;
  }
}

int main() {
  ee_s32 *instr = (ee_s32 *)malloc(sizeof(ee_s32) * 10);
  ee_s32 var = 24;

  for (int i = 0; i < 10; i++) {
    instr[i] = i + 48;
  }

  matrix_add_const(10, instr, var);

  for (int j = 0; j < 10; j++)
    printf("instr[%d] = %d\n", j, instr[j]);
}
