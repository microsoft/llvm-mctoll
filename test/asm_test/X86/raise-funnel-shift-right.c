// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: MRI : SHRD r16, r16, 8
// CHECK-NEXT: Shift 0x1234 by 8
// CHECK-NEXT: Funnel in 0x5678
// CHECK-NEXT: Shifted Val  = 0x7812
// CHECK-NEXT: Funnel in Val = 0x5678
// CHECK-NEXT: MRI : SHRD r32, r32, 16
// CHECK-NEXT: Shift 0x12345678 by 16
// CHECK-NEXT: Funnel in 0x9abcdef0
// CHECK-NEXT: Shifted Val  = 0xdef01234
// CHECK-NEXT: Funnel in Val = 0x9abcdef0
// CHECK-NEXT: MRI : SHRD r64, r64, 24
// CHECK-NEXT: Shift 0x123456789abcdef0 by 24
// CHECK-NEXT: Funnel in 0xdeadbeefdeadbeef
// CHECK-NEXT: Shifted Val  = 0xadbeef123456789a
// CHECK-NEXT: Funnel in Val = 0xdeadbeefdeadbeef
// CHECK-NEXT: MRC : SHRD r16, r16, CL
// CHECK-NEXT: Shift 0x1234 by 8
// CHECK-NEXT: Funnel in 0x5678
// CHECK-NEXT: 16-bit Shifted Val  = 0x7812
// CHECK-NEXT: Funnel in Val = 0x5678
// CHECK-NEXT: MRC : SHRD r32, r32, CL
// CHECK-NEXT: Shift 0x12345678 by 8
// CHECK-NEXT: Funnel in 0x9abcdef0
// CHECK-NEXT: Shifted Val  = 0xf0123456
// CHECK-NEXT: Funnel in Val = 0x9abcdef0
// CHECK-NEXT: MRC : SHRD r64, r64, CL
// CHECK-NEXT: Shift 0x123456789abcdef0 by 8
// CHECK-NEXT: Funnel in 0xdeadbeefdeadbeef
// CHECK-NEXT: Shifted Val  = 0x3456789abcdef0de
// CHECK-NEXT: Funnel in Val = 0xdeadbeefdeadbeef
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

// Funnel shift by 8, a 16-bit 'value' using in value
uint16_t __attribute__((noinline))
funnel_shift_right_8_16rri(uint16_t value, uint16_t in) {
  uint16_t in_res, shifted_val;

  printf("Shift 0x%hx by 8\n", value);
  printf("Funnel in 0x%hx\n", in);

  asm volatile("mov %2, %%bx\n\t"
               "mov %3, %%ax\n\t"
               "shrd $8, %%bx, %%ax\n\t"
               "mov %%bx, %0\n\t"
               "mov %%ax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value)
               : "%ax", "%bx");
  // Shifted result
  printf("Shifted Val  = 0x%hx\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%hx\n", in_res);
  return shifted_val;
}

// Funnel shift by 16, a 32-bit 'value' using 'in' value
uint32_t __attribute__((noinline))
funnel_shift_right_16_32rri(uint32_t value, uint32_t in) {
  uint32_t in_res, shifted_val;

  printf("Shift 0x%x by 16\n", value);
  printf("Funnel in 0x%x\n", in);

  asm volatile("mov %2, %%ebx\n\t"
               "mov %3, %%eax\n\t"
               "shrd $16, %%ebx, %%eax\n\t"
               "mov %%ebx, %0\n\t"
               "mov %%eax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value)
               : "%eax", "%ebx");
  // Shifted result
  printf("Shifted Val  = 0x%x\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%x\n", in_res);
  return shifted_val;
}

// Funnel shift by 24, a 64-bit 'value' using 'in' value
uint64_t __attribute__((noinline))
funnel_shift_right_24_64rri(uint64_t value, uint64_t in) {
  uint64_t in_res, shifted_val;

  printf("Shift 0x%lx by 24\n", value);
  printf("Funnel in 0x%lx\n", in);

  asm volatile("mov %2, %%rbx\n\t"
               "mov %3, %%rax\n\t"
               "shrd $24, %%rbx, %%rax\n\t"
               "mov %%rbx, %0\n\t"
               "mov %%rax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value)
               : "%rax", "%rbx");
  // Shifted result
  printf("Shifted Val  = 0x%lx\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%lx\n", in_res);
  return shifted_val;
}

// Funnel shift by 'count', a 16-bit 'value' using in value
uint16_t __attribute__((noinline))
funnel_shift_right_cl_16rri(uint16_t value, uint16_t in, uint8_t count) {
  uint16_t in_res, shifted_val;

  printf("Shift 0x%hx by %hd\n", value, count);
  printf("Funnel in 0x%hx\n", in);

  asm volatile("mov %2, %%bx\n\t"
               "mov %3, %%ax\n\t"
               "mov %4, %%cl\n\t"
               "shrd %%cl, %%bx, %%ax\n\t"
               "mov %%bx, %0\n\t"
               "mov %%ax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value), "r"(count)
               : "%ax", "%bx", "%cl");
  // Shifted result
  printf("16-bit Shifted Val  = 0x%hx\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%hx\n", in_res);
  return shifted_val;
}

// Funnel shift by 'count', a 32-bit 'value' using in value
uint32_t __attribute__((noinline))
funnel_shift_right_cl_32rri(uint32_t value, uint32_t in, uint8_t count) {
  uint32_t in_res, shifted_val;

  printf("Shift 0x%x by %hd\n", value, count);
  printf("Funnel in 0x%x\n", in);

  asm volatile("mov %2, %%ebx\n\t"
               "mov %3, %%eax\n\t"
               "mov %4, %%cl\n\t"
               "shrd %%cl, %%ebx, %%eax\n\t"
               "mov %%ebx, %0\n\t"
               "mov %%eax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value), "r"(count)
               : "%eax", "%ebx", "%cl");
  // Shifted result
  printf("Shifted Val  = 0x%x\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%x\n", in_res);
  return shifted_val;
}

// Funnel shift by 'count', a 64-bit 'value' using in value
uint64_t __attribute__((noinline))
funnel_shift_right_cl_64rri(uint64_t value, uint64_t in, uint8_t count) {
  uint64_t in_res, shifted_val;

  printf("Shift 0x%lx by %hd\n", value, count);
  printf("Funnel in 0x%lx\n", in);

  asm volatile("mov %2, %%rbx\n\t"
               "mov %3, %%rax\n\t"
               "mov %4, %%cl\n\t"
               "shld %%cl, %%rbx, %%rax\n\t"
               "mov %%rbx, %0\n\t"
               "mov %%rax, %1"
               : "=r"(in_res), "=r"(shifted_val)
               : "r"(in), "r"(value), "r"(count)
               : "%rax", "%rbx", "%cl");
  // Shifted result
  printf("Shifted Val  = 0x%lx\n", shifted_val);
  // Unchanged in val
  printf("Funnel in Val = 0x%lx\n", in_res);
  return shifted_val;
}

// Test various shld instructions
int main() {
  printf("MRI : SHRD r16, r16, 8\n");
  uint16_t s16 = funnel_shift_right_8_16rri(0x1234, 0x5678);
  printf("MRI : SHRD r32, r32, 16\n");
  uint32_t s32 = funnel_shift_right_16_32rri(0x12345678, 0x9abcdef0);
  printf("MRI : SHRD r64, r64, 24\n");
  uint64_t s64 =
      funnel_shift_right_24_64rri(0x123456789abcdef0, 0xdeadbeefdeadbeef);
  printf("MRC : SHRD r16, r16, CL\n");
  uint16_t s16_cl = funnel_shift_right_cl_16rri(0x1234, 0x5678, 8);
  printf("MRC : SHRD r32, r32, CL\n");
  uint32_t s32_cl = funnel_shift_right_cl_32rri(0x12345678, 0x9abcdef0, 8);
  printf("MRC : SHRD r64, r64, CL\n");
  uint64_t s64_cl =
      funnel_shift_right_cl_64rri(0x123456789abcdef0, 0xdeadbeefdeadbeef, 8);
  return 0;
}
