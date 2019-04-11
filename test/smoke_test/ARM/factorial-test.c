// RUN: clang %S/../Inputs/factorial.c -o %t.o -c -mx32 -target armv4t -mfloat-abi=soft
// RUN: arm-none-linux-gnueabi-gcc %t.o -shared -fPIC -o %t.so
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Factorial of 10 3628800

#include <stdio.h>

extern int factorial(int n);

int main() {
  printf("Factorial of 10 %d\n", factorial(10));
  return 0;
}
