// RUN: clang -o %t.o %s --target=%arm_triple
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s

// CHECK: PASS: 1-d BSS Initialization
// CHECK: PASS: 1-d Initialization
// CHECK: PASS: 2-d BSS Initialization
// CHECK: PASS: 2-d Initialization
// CHECK: Arr_2_Glob[10][12] = 10000

#include <stdio.h>

#define ARRAY_SIZE 50
#define ITER_COUNT 10000

int incr(int arr[ARRAY_SIZE][ARRAY_SIZE]) {
  arr[10][12] += 1;
  return 0;
}

int Arr_1_Glob[ARRAY_SIZE];
int Arr_2_Glob[ARRAY_SIZE][ARRAY_SIZE];

int main(int argc, char **argv) {
  Arr_1_Glob[8] = 42;
  Arr_2_Glob[8][7] = 4242;

  if (Arr_1_Glob[0] == 0) {
    printf("PASS: 1-d BSS Initialization\n");
  } else {
    printf("FAIL: 1-d BSS Initialization\n");
  }
  if (Arr_1_Glob[8] == 42) {
    printf("PASS: 1-d Initialization\n");
  } else {
    printf("FAIL: 1-d Initialization\n");
  }

  if (Arr_2_Glob[0][0] == 0) {
    printf("PASS: 2-d BSS Initialization\n");
  } else {
    printf("FAIL: 2-d BSS Initialization\n");
  }
  if (Arr_2_Glob[8][7] == 4242) {
    printf("PASS: 2-d Initialization\n");
  } else {
    printf("FAIL: 2-d Initialization\n");
  }

  // test global array passed as argument
  for (int i = 0; i < ITER_COUNT; i++) {
    incr(Arr_2_Glob);
  }
  printf("Arr_2_Glob[10][12] = %d\n", Arr_2_Glob[10][12]);

  return 0;
}
