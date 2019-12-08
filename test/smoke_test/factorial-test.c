// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/factorial.c -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Factorial of 10 3628800

#include <stdio.h>

extern int factorial(int n);

int main() {
  printf("Factorial of 10 %d\n", factorial(10));
  return 0;
}
