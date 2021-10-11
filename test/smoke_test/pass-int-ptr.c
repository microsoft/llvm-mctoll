// REQUIRES: system-linux
// RUN: clang -O1 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 4
// CHECK-EMPTY

#include <stdio.h>

int x = 4;

__attribute__((noinline))
void print_int(int *ptr) {
  printf("%d\n", *ptr);
}

int main(void) {
  print_int(&x);

  return 0;
}
