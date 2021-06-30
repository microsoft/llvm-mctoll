// REQUIRES: system-linux
// RUN: clang -O1 -fno-inline -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 1.5 + 0.5 = 2.0
// CHECK: 1.5 + 0.5 = 2.0
// CHECK: 1.5 - 0.5 = 1.0
// CHECK: 1.5 - 0.5 = 1.0
// CHECK: 1.5 * 0.5 = 0.75
// CHECK: 1.5 * 0.5 = 0.75
// CHECK: 1.5 / 0.5 = 3.0
// CHECK: 1.5 / 0.5 = 3.0
// CHECK-EMPTY

#include <stdio.h>

float addf(float a, float *b) {
  return a + *b;
}

double addd(double a, double *b) {
  return a + *b;
}

float subf(float a, float *b) {
  return a - *b;
}

double subd(double a, double *b) {
  return a - *b;
}

float mulf(float a, float *b) {
  return a * *b;
}

double muld(double a, double *b) {
  return a * *b;
}

float divf(float a, float *b) {
  return a / *b;
}

double divd(double a, double *b) {
  return a / *b;
}

int main() {
  double argAd = 1.5;
  double argBd = 0.5;
  float argAf = 1.5f;
  float argBf = 0.5f;
  printf("%.1f + %.1f = %.1f\n", argAf, argBf, addf(argAf, &argBf));
  printf("%.1f + %.1f = %.1f\n", argAd, argBd, addd(argAd, &argBd));
  printf("%.1f - %.1f = %.1f\n", argAf, argBf, subf(argAf, &argBf));
  printf("%.1f - %.1f = %.1f\n", argAd, argBd, subd(argAd, &argBd));
  printf("%.1f * %.1f = %.2f\n", argAf, argBf, mulf(argAf, &argBf));
  printf("%.1f * %.1f = %.2f\n", argAd, argBd, muld(argAd, &argBd));
  printf("%.1f / %.1f = %.1f\n", argAf, argBf, divf(argAf, &argBf));
  printf("%.1f / %.1f = %.1f\n", argAd, argBd, divd(argAd, &argBd));

  return 0;
}
