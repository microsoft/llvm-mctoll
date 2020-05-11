// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Double Equal
// CHECK: Float Not Equal
// CHECK-EMPTY


#include <stdio.h>

#define PI_VALUE 3.141592653589793238

int main() {

  double d_pi = PI_VALUE;
  float f_pi = PI_VALUE;

  if (d_pi == PI_VALUE)
    printf("Double Equal\n");
  else
    printf("Double Not Equal\n");

  if (f_pi == PI_VALUE)
    printf("Float Equal\n");
  else
    printf("Float Not Equal\n");

  return 0;
}
