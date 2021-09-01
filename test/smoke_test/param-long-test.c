// REQUIRES: system-linux
// RUN: clang -o %t.so %s -shared -fPIC
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I %S/Inputs/param-long.h %t.so
// RUN: clang -o %t1 %S/Inputs/param-long.c %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: test(0x7fffffffffffffff)
// CHECK-EMPTY

#include <stdio.h>
#include <limits.h>

extern void test(long int x);

int main() {
  test(LONG_MAX);
  return 0;
}
