// REQUIRES: system-linux
// RUN: clang -o %T/libexternvar-lib.so %S/Inputs/externvar-lib.c -fPIC -shared
// RUN: clang %s -o %t -L%T/ -lexternvar-lib
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll -L%T/ -lexternvar-lib
// RUN: export  LD_LIBRARY_PATH=%T/:$PATH
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Result is 304
#include <stdio.h>

extern volatile int j;

int __attribute__((noinline)) foo(int i) {
  i += j;
  i += j;
  i += j;
  return i;
}

int main() {
  int sum = foo(4);
  printf("Result is %d\n", sum);
  return 0;
}
