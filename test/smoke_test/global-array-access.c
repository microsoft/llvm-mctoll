// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s

// CHECK: PASS: 1-d BSS Initialization
// CHECK: PASS: 1-d Initialization
// CHECK: PASS: 2-d BSS Initialization
// CHECK: PASS: 2-d Initialization

#include <stdio.h>

int             Arr_1_Glob [50];
int             Arr_2_Glob [50] [50];

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
  return 0;
}
