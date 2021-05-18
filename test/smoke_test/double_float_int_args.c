// REQUIRES: system-linux
// RUN: clang -O1 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0.5
// CHECK: 3
// CHECK: 1.5
// CHECK: 2.5
// CHECK-EMPTY

#include <stdio.h>

double get_first(double a, int b, double c) {
  return a;
}

int get_second(double a, int b, double c) {
  return b;
}

double get_third(double a, int b, double c) {
  return c;
}

float get_fourth(double a, int b, double c, float d) {
  return d;
}

int main() {
  double a = get_first(0.5, 3, 1.5);
  printf("%.1f\n", a);

  int b = get_second(0.5, 3, 1.5);
  printf("%d\n", b);

  double c = get_third(0.5, 3, 1.5);
  printf("%.1f\n", c);

  float d = get_fourth(0.5, 3, 1.5, 2.5);
  printf("%.1f\n", d);

  return 0;
}
