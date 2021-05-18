// REQUIRES: system-linux
// RUN: clang -O1 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0.5
// CHECK: 1.5
// CHECK-EMPTY

#include <stdio.h>

double get_first(float a, float b) {
  return a;
}

float get_second(float a, float b) {
  return b;
}

int main() {
  float a = get_first(0.5f, 1.5f);
  float b = get_second(0.5f, 1.5f);
  printf("%.1f\n", a);
  printf("%.1f\n", b);
  return 0;
}
