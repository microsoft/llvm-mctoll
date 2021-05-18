// REQUIRES: system-linux
// RUN: clang -O1 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0.5
// CHECK: 1.5
// CHECK-EMPTY

#include <stdio.h>

double get_first(double a, double b) {
  return a;
}

double get_second(double a, double b) {
  return b;
}

int main() {
  double a = get_first(0.5, 1.5);
  double b = get_second(0.5, 1.5);
  printf("%.1f\n", a);
  printf("%.1f\n", b);
  return 0;
}
