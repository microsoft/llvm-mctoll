// REQUIRES: system-linux
// RUN: clang -O0 -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Called function 1
// CHECK: Called function 2
// CHECK: Called function 3
// CHECK-EMPTY

#include <stdio.h>

void func(int i) { printf("Called function %d\n", i); }

int main() {
  void (*functions[3])(int);

  for (int i = 0; i < 3; ++i) {
    functions[i] = func;
  }

  for (int i = 0; i < 3; ++i) {
    functions[i](i + 1);
  }

  return 0;
}
