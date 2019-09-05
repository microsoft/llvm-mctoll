// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: foo value 3

#include <stdio.h>
int __attribute__((noinline)) foo(short seed) {
  switch (seed) {
  case 3:
    printf("foo value 3\n");
    break;
  case 4:
    printf("foo value 4\n");
    break;
  default:
    break;
  }
  return 1;
}

int main() {
  short seed = 3;
  int a = foo(seed);
  printf("result %d", a);
  return 0;
}
