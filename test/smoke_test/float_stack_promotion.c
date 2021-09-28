// REQUIRES: system-linux
// RUN: clang -O3 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: val = 1.0
// CHECK-EMPTY

#include <stdio.h>

int main(int argc, char **argv) {
  double val = 1.0;

  if (argc == 2) {
    val = 2.0;
  } else if (argc > 2) {
    val = 3.0;
  }

  printf("val = %.1f\n", val);

  return 0;
}
