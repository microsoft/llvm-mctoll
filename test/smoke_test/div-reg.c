#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s

// CHECK: Result : 2
// CHECK: Result : 25
// CHECK: Result : 250
// CHECK: Result : 2500

int main() {
  uint8_t a = 10;
  uint16_t b = 100;
  uint32_t c = 1000;
  uint64_t d = 10000;

  a = a / 2;
  b = b / 2;
  c = c / 2;
  d = d / 2;

  printf("Result : %" PRIu8 "\n", a / 2);
  printf("Result : %" PRIu16 "\n", b / 2);
  printf("Result : %" PRIu32 "\n", c / 2);
  printf("Result : %" PRIu64 "\n", d / 2);
  return 0;
}
