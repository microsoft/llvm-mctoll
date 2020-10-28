// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/reduce.c -shared -fPIC -Os
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Sum of [0, 10] 55

#include <stdio.h>

int main() {
  int arr[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  printf("Sum of [0, 10] %d\n", sum(arr, 11));
  return 0;
}
