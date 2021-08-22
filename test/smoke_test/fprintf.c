// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: x = 0, y = 0, z = 1
// CHECK-EMPTY

#include <stdio.h>

int x;
int y = 0;
int z = 1;

int main() {
  fprintf(stdout, "x = %d, y = %d, z = %d\n", x, y, z);

  return 0;
}
