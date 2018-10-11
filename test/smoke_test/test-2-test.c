// RUN: clang -o %t.so %S/Inputs/test-2.c -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: test_2_func result 7

#include <stdio.h>

extern long test_2_func(int a, long b);

int main() {
  printf("test_2_func result %ld\n", test_2_func(2, 3));
  return 0;
}
