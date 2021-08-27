// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/assert.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: argc == 1
// CHECK-EMPTY

#include <stdio.h>
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 1);
  printf("argc == 1\n");
  return 0;
}
