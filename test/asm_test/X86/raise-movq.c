// REQUIRES: system-linux
// RUN: clang -O1 -fno-inline -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0x4045400000000000, 0x422a0000
// CHECK: 42.5, 42.5
// CHECK-EMPTY

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

void movq_fp_to_gp(double a, float b) {
  uint64_t c = *(uint64_t *)&a;
  uint32_t d = *(uint32_t *)&b;
  printf("0x%016" PRIx64 ", 0x%08x\n", c, d);
}

void movq_gp_to_fp(uint64_t a, uint32_t b) {
  double c = *(double *)&a;
  float d = *(float *)&b;
  printf("%.1f, %.1f\n", c, d);
}

int main() {
  double a = 42.5;
  float b = 42.5;

  movq_fp_to_gp(a, b);
  movq_gp_to_fp(*(uint64_t *)&a, *(uint32_t *)&b);

  return 0;
}
