#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s

// CHECK: Result : 2
// CHECK: Result : 25
// CHECK: Result : 250
// CHECK: Result : 2500
// CHECK: Int_1 = 1
// CHECK: Int_2 = 13
// CHECK: Int_3 = 7
// CHECK: q = 0x53 r = 0x1
// CHECK: q = 0xfffffffe r = 0x0
// CHECK: q = 0x5f8 r = 0xc
// CHECK: q = 0xffffffe0 r = 0xfffffffc
// CHECK: q = 0x5de09 r = 0x2331
// CHECK: q = 0xffffe079 r = 0xfffff8f1
// CHECK: q = 0x7d5dfff r = 0x1ff82a2001
// CHECK: q = 0xffffffffffd5e001 r = 0xffffffe0002a1fff

void __attribute__((noinline)) div8_test(uint8_t dd,
					 uint8_t dv) {
  uint8_t  q = dd / dv;
  uint8_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) idiv8_test(int8_t dd,
					  int8_t dv) {
  int16_t  q = dd / dv;
  int16_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) div16_test(uint16_t dd,
					  uint16_t dv) {
  uint16_t  q = dd / dv;
  uint16_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) idiv16_test(int16_t dd,
					   int16_t dv) {
  int16_t  q = dd / dv;
  int16_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) div32_test(uint32_t dd,
					  uint32_t dv) {
  uint32_t  q = dd / dv;
  uint32_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) idiv32_test(int32_t dd,
					   int32_t dv) {
  int32_t  q = dd / dv;
  int32_t  r = dd % dv;
  printf("q = 0x%x r = 0x%x\n", q, r);
  return;
}

void __attribute__((noinline)) div64_test(uint64_t dd,
					  uint64_t dv) {
  uint64_t  q = dd / dv;
  uint64_t  r = dd % dv;
  printf("q = 0x%lx r = 0x%lx\n", q, r);
  return;
}

void __attribute__((noinline)) idiv64_test(int64_t dd,
					   int64_t dv) {
  int64_t  q = dd / dv;
  int64_t  r = dd % dv;
  printf("q = 0x%lx r = 0x%lx\n", q, r);
  return;
}

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

  // More division tests
  div8_test(0xfa, 0x3);
  idiv8_test(0xfa, 0x3);
  div16_test(0xfabc, 0x2a);
  idiv16_test(0xfabc, 0x2a);
  div32_test(0xfabcabcd, 0x2abc);
  idiv32_test(0xfabcabcd, 0x2abc);
  div64_test(0xfabc000000000000, 0x0000002000000001);
  idiv64_test(0xfabc000000000000, 0x0000002000000001);

  return 0;
}
