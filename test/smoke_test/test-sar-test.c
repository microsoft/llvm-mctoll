// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Expect: 250

#include <stdio.h>

int __attribute__ ((noinline)) printVal(int a) {
  int ret = a >> 2;
  return ret;
}

int main() {
  int a = 1000;
  int prt = printVal(a);
  printf("Expect: %d\n", prt);
  return 0;
}
