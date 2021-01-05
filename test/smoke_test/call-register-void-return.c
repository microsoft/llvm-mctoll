// REQUIRES: system-linux
// RUN: clang -o %t-clang-noopt %s 
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-clang-noopt
// RUN: clang -o %t-clang-noopt-dis %t-clang-noopt-dis.ll
// RUN: %t-clang-noopt-dis 2>&1 | FileCheck %s 

// RUN: gcc -o %t-gcc-noopt %s 
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-gcc-noopt
// RUN: clang -o %t-gcc-noopt-dis %t-gcc-noopt-dis.ll
// RUN: %t-gcc-noopt-dis 2>&1 | FileCheck %s

// CHECK: 20  + 5 = 25
// CHECK_NEXT: 20  - 5 = 15
// CHECK_NEXT: 20  * 5 = 100

#include <stdio.h>

void __attribute__((noinline)) add(int op1, int op2) {
  printf("%d  + %d = %d\n", op1, op2, op1 + op2);
}

void __attribute__((noinline)) sub(int op1, int op2) {
  printf("%d  - %d = %d\n", op1, op2, op1 - op2);
}

void __attribute__((noinline)) mul(int op1, int op2) {
  printf("%d  * %d = %d\n", op1, op2, op1 * op2);
}

void __attribute__((noinline)) binary_op(void (*f)(int, int), int a, int b) {
  (*f)(a, b);
}

int main(int argc, char **argv) {
  binary_op(&add, 20, 5);   
  binary_op(&sub, 20, 5);   
  binary_op(&mul, 20, 5);   
  return 0;
}
