#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s

// CHECK: Result : 2
// CHECK: Result : 25
// CHECK: Result : 250
// CHECK: Result : 2500
// CHECK: Int_1 = 1
// CHECK: Int_2 = 13
// CHECK: Int_3 = 7

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

  int Int_1 = 3;
  int Int_2 = 3;
  int Int_3 = 7;

  Int_2 = Int_2 * Int_1;
  Int_1 = Int_2 / Int_3;
  Int_2 = 7 * (Int_2 - Int_3) - Int_1;

  printf("Int_1 = %d\n", Int_1);
  printf("Int_2 = %d\n", Int_2);
  printf("Int_3 = %d\n", Int_3);
  return 0;
}
