// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: ROR 0x2e by 1
// CHECK-NEXT: Result : 0x17 OF = 0 CF = 0
// CHECK-NEXT: ROR 0xcd by 1
// CHECK-NEXT: Result : 0xe6 OF = 0 CF = 1
// CHECK-NEXT: ROR 0xf0 by 1
// CHECK-NEXT: Result : 0x78 OF = 1 CF = 0
// CHECK-NEXT: ROR 0xd by 1
// CHECK-NEXT: Result : 0x86 OF = 1 CF = 1
// CHECK-NEXT: ROR 0x2 by 4
// CHECK-NEXT: Result : 0x20 OF = 0 CF = 0
// CHECK-NEXT: ROR 0xa by 4
// CHECK-NEXT: Result : 0xa0 OF = 0 CF = 1
// CHECK-NEXT: ROR 0x2e by 1
// CHECK-NEXT: Result : 0x17 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x8001 by 1
// CHECK-NEXT: Result : 0xc000 OF = 0 CF = 1
// CHECK-NEXT: ROR 0xc000 by 1
// CHECK-NEXT: Result : 0x6000 OF = 1 CF = 0
// CHECK-NEXT: ROR 0xd by 1
// CHECK-NEXT: Result : 0x8006 OF = 1 CF = 1
// CHECK-NEXT: ROR 0x200 by 8
// CHECK-NEXT: Result : 0x2 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x8080 by 8
// CHECK-NEXT: Result : 0x8080 OF = 0 CF = 1
// CHECK-NEXT: ROR 0x2e by 1
// CHECK-NEXT: Result : 0x17 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x80000001 by 1
// CHECK-NEXT: Result : 0xc0000000 OF = 0 CF = 1
// CHECK-NEXT: ROR 0xc0000000 by 1
// CHECK-NEXT: Result : 0x60000000 OF = 1 CF = 0
// CHECK-NEXT: ROR 0xd by 1
// CHECK-NEXT: Result : 0x80000006 OF = 1 CF = 1
// CHECK-NEXT: ROR 0x10000200 by 8
// CHECK-NEXT: Result : 0x100002 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x10008080 by 8
// CHECK-NEXT: Result : 0x80100080 OF = 0 CF = 1
// CHECK-NEXT: ROR 0x2e by 1
// CHECK-NEXT: Result : 0x17 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x8000000000000001 by 1
// CHECK-NEXT: Result : 0xc000000000000000 OF = 0 CF = 1
// CHECK-NEXT: ROR 0xc000000000000000 by 1
// CHECK-NEXT: Result : 0x6000000000000000 OF = 1 CF = 0
// CHECK-NEXT: ROR 0xd by 1
// CHECK-NEXT: Result : 0x8000000000000006 OF = 1 CF = 1
// CHECK-NEXT: ROR 0x1000000000000200 by 8
// CHECK-NEXT: Result : 0x10000000000002 OF = 0 CF = 0
// CHECK-NEXT: ROR 0x1000000000008080 by 8
// CHECK-NEXT: Result : 0x8010000000000080 OF = 0 CF = 1
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

/* Test raising ror instruction with register operand and immediate operand
   that is either 1 or greater than 1.
   Also test the correctness of flags set by the ror instruction.
*/

// Compute ror of 8-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROR8r1
uint8_t __attribute__((noinline)) rotate_right_8r_imm1(uint8_t val) {
  uint8_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 1\n", val);
  __asm__("mov %3, %%al \n"
          "ror %4, %%al \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%al, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(1)                 /* input */
          : "%al", "%bl", "%cl"              /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 8-bit register by 4
// Print rotated value as well as affected flags OF and CF
// ROR8ri
uint8_t __attribute__((noinline)) rotate_right_8r_imm4(uint8_t val) {
  uint8_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 4\n", val);
  __asm__("mov %3, %%al \n"
          "ror %4, %%al \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%al, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(4)                 /* input */
          : "%al", "%bl", "%cl"              /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 16-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROR16r1
uint16_t __attribute__((noinline)) rotate_right_16r_imm1(uint16_t val) {
  uint16_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 1\n", val);
  __asm__("mov %3, %%ax \n"
          "ror %4, %%ax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%ax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(1)                 /* input */
          : "%ax", "%bl", "%cl"              /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 16-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROR16ri
uint16_t __attribute__((noinline)) rotate_right_16r_imm8(uint16_t val) {
  uint16_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 8\n", val);
  __asm__("mov %3, %%ax \n"
          "ror %4, %%ax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%ax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(8)                 /* input */
          : "%ax", "%bl", "%cl"              /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 32-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROR32r1
uint32_t __attribute__((noinline)) rotate_right_32r_imm1(uint32_t val) {
  uint32_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 1\n", val);
  __asm__("mov %3, %%eax \n"
          "ror %4, %%eax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%eax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(1)                 /* input */
          : "%eax", "%bl", "%cl"             /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 32-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROR32ri
uint32_t __attribute__((noinline)) rotate_right_32r_imm8(uint32_t val) {
  uint32_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%x by 8\n", val);
  __asm__("mov %3, %%eax \n"
          "ror %4, %%eax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%eax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(8)                 /* input */
          : "%eax", "%bl", "%cl"             /* clobbered register */
  );
  printf("Result : 0x%x OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 64-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROR64r1
uint64_t __attribute__((noinline)) rotate_right_64r_imm1(uint64_t val) {
  uint64_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%lx by 1\n", val);
  __asm__("mov %3, %%rax \n"
          "ror %4, %%rax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%rax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(1)                 /* input */
          : "%rax", "%bl", "%cl"             /* clobbered register */
  );
  printf("Result : 0x%lx OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Compute ror of 64-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROR64ri
uint64_t __attribute__((noinline)) rotate_right_64r_imm8(uint64_t val) {
  uint64_t result;
  uint8_t of = 0, cf = 0;
  printf("ROR 0x%lx by 8\n", val);
  __asm__("mov %3, %%rax \n"
          "ror %4, %%rax \n"
          "seto %%bl\n"
          "setc %%cl\n"
          "mov %%rax, %0 \n"
          "mov %%bl, %1\n"
          "mov %%cl, %2\n"
          : "=r"(result), "=r"(of), "=r"(cf) /* output */
          : "r"(val), "i"(8)                 /* input */
          : "%rax", "%bl", "%cl"             /* clobbered register */
  );
  printf("Result : 0x%lx OF = %hd CF = %hd\n", result, of, cf);
  return result;
}

// Test raising of rotate instruction
int main() {
  // ROR 8-bit by 1
  // OF 0; CF 0
  uint8_t s_eax_8 = rotate_right_8r_imm1(0x2e);
  // OF 0; CF 1
  s_eax_8 = rotate_right_8r_imm1(0xcd);
  // OF 1; CF 0
  s_eax_8 = rotate_right_8r_imm1(0xf0);
  // OF 1; CF 1
  s_eax_8 = rotate_right_8r_imm1(0x0d);

  // ROR 8-bit value by > 1
  // OF uneffected; CF 0
  s_eax_8 = rotate_right_8r_imm4(0x02);
  // OF uneffected; CF 1
  s_eax_8 = rotate_right_8r_imm4(0x0a);

  // ROR 16-bit value by 1
  // OF 0; CF 0
  uint16_t s_eax_16 = rotate_right_16r_imm1(0x002e);
  // OF 0; CF 1
  s_eax_16 = rotate_right_16r_imm1(0x8001);
  // OF 1; CF 0
  s_eax_16 = rotate_right_16r_imm1(0xc000);
  // OF 1; CF 1
  s_eax_16 = rotate_right_16r_imm1(0x000d);

  // ROR 16-bit value by > 1
  // OF uneffected; CF 0
  s_eax_16 = rotate_right_16r_imm8(0x0200);
  // OF uneffected; CF 1
  s_eax_8 = rotate_right_16r_imm8(0x8080);

  // ROR 32-bit value by 1
  // OF 0; CF 0
  uint32_t s_eax_32 = rotate_right_32r_imm1(0x0000002e);
  // OF 0; CF 1
  s_eax_32 = rotate_right_32r_imm1(0x80000001);
  // OF 1; CF 0
  s_eax_32 = rotate_right_32r_imm1(0xc0000000);
  // OF 1 CF 1
  s_eax_32 = rotate_right_32r_imm1(0x0000000d);

  // ROR 32-bit value by > 1
  // OF uneffected; CF 0
  s_eax_32 = rotate_right_32r_imm8(0x10000200);
  // OF uneffected; CF 1
  s_eax_8 = rotate_right_32r_imm8(0x10008080);

  // ROR 64-bit value by 1
  // OF 0; CF 0
  uint64_t s_eax_64 = rotate_right_64r_imm1(0x000000000000002e);
  // OF 0; CF 1
  s_eax_64 = rotate_right_64r_imm1(0x8000000000000001);
  // OF 1; CF 0
  s_eax_64 = rotate_right_64r_imm1(0xc000000000000000);
  // OF 1; CF 1
  s_eax_64 = rotate_right_64r_imm1(0x000000000000000d);

  // ROR 64-bit value by > 1
  // OF uneffected; CF 0
  s_eax_64 = rotate_right_64r_imm8(0x1000000000000200);
  // OF uneffected; CF 1
  s_eax_8 = rotate_right_64r_imm8(0x1000000000008080);

  return 0;
}
