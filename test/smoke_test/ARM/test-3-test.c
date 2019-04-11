// RUN: clang %S/../Inputs/test-3.c -o %t.o -c -mx32 -target armv4t -mfloat-abi=soft
// RUN: arm-none-linux-gnueabi-gcc %t.o -shared -fPIC -o %t.so
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: test_3_func result 66

#include <stdio.h>

extern int test_3_func(int a, int b);

int main() {
  printf("test_3_func result %d\n", test_3_func(234, 300));
  return 0;
}
