// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/fibfunc.c -shared -fPIC
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s -check-prefix=CLANG
// CLANG: Fibonacci of 42 433494437

// RUN: gcc -o %t-gcc %s %S/Inputs/fibfunc.c
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-gcc -o %t-gcc-dis.ll
// RUN: clang -o %t-gcc-dis %t-gcc-dis.ll
// RUN: %t-gcc-dis 2>&1 | FileCheck %s -check-prefix=GCC
// GCC: Fibonacci of 42 433494437

#include <stdio.h>

extern long fib(long n);

int main() {
  printf("Fibonacci of 42 %ld\n", fib(42));
  return 0;
}
