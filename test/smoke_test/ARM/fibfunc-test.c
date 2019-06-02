// RUN: clang %S/../Inputs/fibfunc.c -o %t.so --target=%arm_triple -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Fibonacci of 42 433494437

#include <stdio.h>

extern long fib(long n);

int main() {
  printf("Fibonacci of 42 %ld\n", fib(42));
  return 0;
}
