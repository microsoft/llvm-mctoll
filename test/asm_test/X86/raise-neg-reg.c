// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Value to Negate 0x1234
// CHECK-NEXT: Negated Val  = 0xffffedcc
// CHECK-NEXT: Value to Negate 0x12345678
// CHECK-NEXT: Negated Val  = 0xedcba988
// CHECK-NEXT: Value to Negate 0x123456789abcdef0
// CHECK-NEXT: Negated Val  = 0xedcba98765432110
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

// Compute two's complement of a 16-bit value in register
uint16_t __attribute__((noinline)) twos_complement_16r(uint16_t value) {
  uint16_t shifted_val;

  printf("Value to Negate 0x%hx\n", value);

  asm volatile("mov %1, %%bx\n\t"
               "neg %%bx\n\t"
               "mov %%bx, %0"
               : "=r"(shifted_val)
               : "r"(value)
               : "%bx");
  // Shifted result
  printf("Negated Val  = 0x%hx\n", shifted_val);
  return shifted_val;
}

// Compute two's complement of a 32-bit value in register
uint32_t __attribute__((noinline)) twos_complement_32r(uint32_t value) {
  uint32_t shifted_val;

  printf("Value to Negate 0x%x\n", value);

  asm volatile("mov %1, %%ebx\n\t"
               "neg %%ebx\n\t"
               "mov %%ebx, %0"
               : "=r"(shifted_val)
               : "r"(value)
               : "%ebx");
  // Shifted result
  printf("Negated Val  = 0x%x\n", shifted_val);
  return shifted_val;
}

// Compute two's complement of a 64-bit value in register
uint64_t __attribute__((noinline)) twos_complement_64r(uint64_t value) {
  uint64_t shifted_val;

  printf("Value to Negate 0x%lx\n", value);

  asm volatile("mov %1, %%rbx\n\t"
               "neg %%rbx\n\t"
               "mov %%rbx, %0"
               : "=r"(shifted_val)
               : "r"(value)
               : "%rbx");
  // Shifted result
  printf("Negated Val  = 0x%lx\n", shifted_val);
  return shifted_val;
}

// Test raising of neg instruction
int main() {
  uint16_t s16 = twos_complement_32r(0x1234);
  uint32_t s32 = twos_complement_32r(0x12345678);
  uint64_t s64 = twos_complement_64r(0x123456789abcdef0);
  return 0;
}
