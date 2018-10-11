// RUN: clang -o %t.so %S/Inputs/fibfunc.c -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Fibonacci of 42 433494437

#include <stdio.h>

extern long fib(long n);

int main() {
  printf("Fibonacci of 42 %ld\n", fib(42));
  return 0;
}
