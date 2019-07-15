// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: foo: 26

/* foo() will raise the instructon of RETQ in bb.4.
 */

#include <stdio.h>
short B[4] = {0, 1, 2, 3};

unsigned foo(short *B, int n) {
  unsigned sum = 0;
  for (int i = 0; i < n; ++i)
      sum += B[i] + 5;
  return sum;
}

int main() {
  int N5 = 4;
  unsigned sum_relsult = foo(B, N5);
  printf("foo: %d \n", sum_relsult);
  return 0;
}
