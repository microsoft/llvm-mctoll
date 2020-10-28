// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: ROL 0xbd by 1
// CHECK-NEXT: Result : 0x7b OF = 1 CF = 1
// CHECK-NEXT: ROL 0xcd by 1
// CHECK-NEXT: Result : 0x9b OF = 0 CF = 1
// CHECK-NEXT: ROL 0xd by 1
// CHECK-NEXT: Result : 0x1a OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd00 by 1
// CHECK-NEXT: Result : 0x7a01 OF = 1 CF = 1
// CHECK-NEXT: ROL 0xcd00 by 1
// CHECK-NEXT: Result : 0x9a01 OF = 0 CF = 1
// CHECK-NEXT: ROL 0xd00 by 1
// CHECK-NEXT: Result : 0x1a00 OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd000000 by 1
// CHECK-NEXT: Result : 0x7a000001 OF = 1 CF = 1
// CHECK-NEXT: ROL 0xcd000000 by 1
// CHECK-NEXT: Result : 0x9a000001 OF = 0 CF = 1
// CHECK-NEXT: ROL 0xd000000 by 1
// CHECK-NEXT: Result : 0x1a000000 OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd00000000000000 by 1
// CHECK-NEXT: Result : 0x7a00000000000001 OF = 1 CF = 1
// CHECK-NEXT: ROL 0xcd00000000000000 by 1
// CHECK-NEXT: Result : 0x9a00000000000001 OF = 0 CF = 1
// CHECK-NEXT: ROL 0xd00000000000000 by 1
// CHECK-NEXT: Result : 0x1a00000000000000 OF = 0 CF = 0
// CHECK-NEXT: ROL 0xf7 by 4
// CHECK-NEXT: Result : 0x7f OF = 0 CF = 1
// CHECK-NEXT: ROL 0xcd by 4
// CHECK-NEXT: Result : 0xdc OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd00 by 8
// CHECK-NEXT: Result : 0xbd OF = 0 CF = 1
// CHECK-NEXT: ROL 0xdc00 by 8
// CHECK-NEXT: Result : 0xdc OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd000000 by 8
// CHECK-NEXT: Result : 0xbd OF = 0 CF = 1
// CHECK-NEXT: ROL 0xdc000000 by 8
// CHECK-NEXT: Result : 0xdc OF = 0 CF = 0
// CHECK-NEXT: ROL 0xbd00000000000000 by 8
// CHECK-NEXT: Result : 0xbd OF = 0 CF = 1
// CHECK-NEXT: ROL 0xdc00000000000000 by 8
// CHECK-NEXT: Result : 0xdc OF = 0 CF = 0
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

/* Test raising rol instruction with register operand and immediate operand
   that is either 1 or greater than 1.
   Also test the correctness of flags set by the rol instruction.
*/

// Compute rol of 8-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROL8r1
uint8_t __attribute__((noinline)) rotate_left_8r_imm1(uint8_t val) {
  uint8_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 1\n", val);
  __asm__("mov %3, %%al \n"
          "rol %4, %%al \n"
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

// Compute rol of 8-bit register by 4
// Print rotated value as well as affected flags OF and CF
// ROL8ri
uint8_t __attribute__((noinline)) rotate_left_8r_imm4(uint8_t val) {
  uint8_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 4\n", val);
  __asm__("mov %3, %%al \n"
          "rol %4, %%al \n"
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

// Compute rol of 16-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROL16r1
uint16_t __attribute__((noinline)) rotate_left_16r_imm1(uint16_t val) {
  uint16_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 1\n", val);
  __asm__("mov %3, %%ax \n"
          "rol %4, %%ax \n"
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

// Compute rol of 16-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROL16ri
uint16_t __attribute__((noinline)) rotate_left_16r_imm8(uint16_t val) {
  uint16_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 8\n", val);
  __asm__("mov %3, %%ax \n"
          "rol %4, %%ax \n"
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

// Compute rol of 32-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROL32r1
uint32_t __attribute__((noinline)) rotate_left_32r_imm1(uint32_t val) {
  uint32_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 1\n", val);
  __asm__("mov %3, %%eax \n"
          "rol %4, %%eax \n"
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

// Compute rol of 32-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROL32ri
uint32_t __attribute__((noinline)) rotate_left_32r_imm8(uint32_t val) {
  uint32_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%x by 8\n", val);
  __asm__("mov %3, %%eax \n"
          "rol %4, %%eax \n"
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

// Compute rol of 64-bit register by 1
// Print rotated value as well as affected flags OF and CF
// ROL64r1
uint64_t __attribute__((noinline)) rotate_left_64r_imm1(uint64_t val) {
  uint64_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%lx by 1\n", val);
  __asm__("mov %3, %%rax \n"
          "rol %4, %%rax \n"
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

// Compute rol of 64-bit register by 8
// Print rotated value as well as affected flags OF and CF
// ROL64ri
uint64_t __attribute__((noinline)) rotate_left_64r_imm8(uint64_t val) {
  uint64_t result;
  uint8_t of = 0, cf = 0;
  printf("ROL 0x%lx by 8\n", val);
  __asm__("mov %3, %%rax \n"
          "rol %4, %%rax \n"
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
  // 1-bit rol
  // OF is set; CF is set
  uint8_t s_eax_8 = rotate_left_8r_imm1(0xbd);
  // OF is cleared; CF is set
  s_eax_8 = rotate_left_8r_imm1(0xcd);
  // OF is cleared; CF is cleared
  s_eax_8 = rotate_left_8r_imm1(0x0d);

  // OF is set; CF is set
  uint16_t s_eax_16 = rotate_left_16r_imm1(0xbd00);
  // OF is cleared; CF is set
  s_eax_16 = rotate_left_16r_imm1(0xcd00);
  // OF is cleared; CF is cleared
  s_eax_16 = rotate_left_16r_imm1(0x0d00);

  // OF is set; CF is set
  uint32_t s_eax_32 = rotate_left_32r_imm1(0xbd000000);
  // OF is cleared; CF is set
  s_eax_32 = rotate_left_32r_imm1(0xcd000000);
  // OF is cleared; CF is cleared
  s_eax_32 = rotate_left_32r_imm1(0x0d000000);

  // OF is set; CF is set
  uint64_t s_eax_64 = rotate_left_64r_imm1(0xbd00000000000000);
  // OF is cleared; CF is set
  s_eax_64 = rotate_left_64r_imm1(0xcd00000000000000);
  // OF is cleared; CF is cleared
  s_eax_64 = rotate_left_64r_imm1(0x0d00000000000000);

  // Rotate by an immediate value other than 1
  // OF is not affected or set since this is not a 1-bit rotate; CF is set
  uint8_t s4_eax_8 = rotate_left_8r_imm4(0xf7);
  // OF is not affected or set since this is not a 1-bit rotate; CF is cleared
  s4_eax_8 = rotate_left_8r_imm4(0xcd);

  // OF is not affected or set since this is not a 1-bit rotate; CF is set
  uint16_t s8_eax_16 = rotate_left_16r_imm8(0xbd00);
  // OF is not affected or set since this is not a 1-bit rotate; CF is cleared
  s8_eax_16 = rotate_left_16r_imm8(0xdc00);

  // OF is not affected or set since this is not a 1-bit rotate; CF is set
  uint32_t s8_eax_32 = rotate_left_32r_imm8(0xbd000000);
  // OF is not affected or set since this is not a 1-bit rotate; CF is cleared
  s8_eax_32 = rotate_left_32r_imm8(0xdc000000);

  // OF is not affected or set since this is not a 1-bit rotate; CF is set
  uint64_t s8_eax_64 = rotate_left_64r_imm8(0xbd00000000000000);
  // OF is not affected or set since this is not a 1-bit rotate; CF is cleared
  s8_eax_64 = rotate_left_64r_imm8(0xdc00000000000000);

  return 0;
}
