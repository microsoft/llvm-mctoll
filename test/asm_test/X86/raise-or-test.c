// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: [Implicit AL]
// CHECK-NEXT: Test 0x21 OR 0x12
// CHECK-NEXT: Result : 0x33
// CHECK-NEXT: [Non-AL]
// CHECK-NEXT: Test 0x21 OR 0x12
// CHECK-NEXT: Result : 0x33
// CHECK-NEXT: [Implicit AX]
// CHECK-NEXT: Test 0x21 OR 0x12
// CHECK-NEXT: Result : 0x33
// CHECK-NEXT: [Implicit AX]
// CHECK-NEXT: Test 0x4321 OR 0x1234
// CHECK-NEXT: Result : 0x5335
// CHECK-NEXT: [Non-AX]
// CHECK-NEXT: Test 0x4321 OR 0x1234
// CHECK-NEXT: Result : 0x5335
// CHECK-NEXT: [Implicit EAX]
// CHECK-NEXT: Test 0xcd00 OR 0x12345678
// CHECK-NEXT: Result : 0x1234df78
// CHECK-NEXT: [Non-EAX]
// CHECK-NEXT: Test 0xcd00 OR 0x12345678
// CHECK-NEXT: Result : 0x1234df78
// CHECK-NEXT: [Implicit RAX]
// CHECK-NEXT: Test 0xcd00abcdef OR 0x12345678
// CHECK-NEXT: Result : 0xcd12bfdfff
// CHECK-NEXT: [Non-RAX]
// CHECK-NEXT: Test 0xcd00abcdef OR 0x12
// CHECK-NEXT: Result : 0xcd00abcdff
// CHECK-NEXT: [Non-RAX]
// CHECK-NEXT: Test 0xcd00abcdef OR 0x12345678
// CHECK-NEXT: Result : 0xcd12bfdfff
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

// Compute or of implicit al and imm
// OR8i8
uint8_t __attribute__((noinline)) or_implicit_al_imm(uint8_t val) {
  uint8_t result;
  printf("[Implicit AL]\nTest 0x%x OR 0x12\n", val);
  __asm__("mov %1, %%al \n"
	  "orb %2, %%al \n"
	  "mov %%al, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12)      /* input */
	  : "%al"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of non-al register and imm
// OR8ri
uint8_t __attribute__((noinline)) or_register_8_imm(uint8_t val) {
  uint8_t result;
  printf("[Non-AL]\nTest 0x%x OR 0x12\n", val);
  __asm__("mov %1, %%bl \n"
	  "orb %2, %%bl \n"
	  "mov %%bl, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12)      /* input */
	  : "%bl"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of implicit ax and imm8
// OR16ri8
uint16_t __attribute__((noinline)) or_implicit_ax_imm8(uint16_t val) {
  uint16_t result;
  printf("[Implicit AX]\nTest 0x%x OR 0x12\n", val);
  __asm__("mov %1, %%ax \n"
	  "or %2, %%ax \n"
	  "mov %%ax, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12)      /* input */
	  : "%ax"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of implicit ax and imm16
// OR16ri16
uint16_t __attribute__((noinline)) or_implicit_ax_imm16(uint16_t val) {
  uint16_t result;
  printf("[Implicit AX]\nTest 0x%x OR 0x1234\n", val);
  __asm__("mov %1, %%ax \n"
	  "or %2, %%ax \n"
	  "mov %%ax, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x1234)      /* input */
	  : "%ax"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of non-ax and imm
// OR16ri
uint16_t __attribute__((noinline)) or_register_16_imm(uint16_t val) {
  uint16_t result;
  printf("[Non-AX]\nTest 0x%x OR 0x1234\n", val);
  __asm__("mov %1, %%bx \n"
	  "or %2, %%bx \n"
	  "mov %%bx, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x1234)      /* input */
	  : "%bx"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of implicit eax and imm32
// OR32i32
uint32_t __attribute__((noinline)) or_implicit_eax_imm32(uint32_t val) {
  uint32_t result;
  printf("[Implicit EAX]\nTest 0x%x OR 0x12345678\n", val);
  __asm__("mov %1, %%eax \n"
	  "or %2, %%eax \n"
	  "movl %%eax, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12345678)      /* input */
	  : "%eax"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of non-eax register and imm32
// OR32ri
uint32_t __attribute__((noinline)) or_register_32_imm32(uint32_t val) {
  uint32_t result;
  printf("[Non-EAX]\nTest 0x%x OR 0x12345678\n", val);
  __asm__("mov %1, %%ebx \n"
	  "or %2, %%ebx \n"
	  "movl %%ebx, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12345678)      /* input */
	  : "%ebx"         /* clobbered register */
	  );
  printf("Result : 0x%x\n", result);
  return result;
}

// Compute or of implicit eax and imm32
// OR64i32
uint64_t __attribute__((noinline)) or_implicit_rax_imm32(uint64_t val) {
  uint64_t result;
  printf("[Implicit RAX]\nTest 0x%lx OR 0x12345678\n", val);
  __asm__("mov %1, %%rax \n"
	  "or %2, %%rax \n"
	  "mov %%rax, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12345678)      /* input */
	  : "%rax"         /* clobbered register */
	  );
  printf("Result : 0x%lx\n", result);
  return result;
}

// Compute or of implicit eax and imm8
// OR64ri8
uint64_t __attribute__((noinline)) or_register_64_imm8(uint64_t val) {
  uint64_t result;
  printf("[Non-RAX]\nTest 0x%lx OR 0x12\n", val);
  __asm__("mov %1, %%rbx \n"
	  "or %2, %%rbx \n"
	  "mov %%rbx, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12)      /* input */
	  : "%rbx"         /* clobbered register */
	  );
  printf("Result : 0x%lx\n", result);
  return result;
}

// Compute or of implicit eax and imm32
// OR64ri32
uint64_t __attribute__((noinline)) or_register_64_imm32(uint64_t val) {
  uint64_t result;
  printf("[Non-RAX]\nTest 0x%lx OR 0x12345678\n", val);
  __asm__("mov %1, %%rbx \n"
	  "or %2, %%rbx \n"
	  "mov %%rbx, %0 \n"
	  : "=r"(result) /* output */
	  : "r"(val), "i"(0x12345678)      /* input */
	  : "%rbx"         /* clobbered register */
	  );
  printf("Result : 0x%lx\n", result);
  return result;
}

// Test raising of neg instruction
int main() {
  uint8_t s_al = or_implicit_al_imm(0x21);
  uint8_t s_reg = or_register_8_imm(0x21);
  uint16_t s_ax_i8 = or_implicit_ax_imm8(0x21);
  uint16_t s_ax_i16 = or_implicit_ax_imm16(0x4321);
  uint16_t s_reg_i16 = or_register_16_imm(0x4321);
  uint32_t s_eax_32 = or_implicit_eax_imm32(0xcd00);
  uint32_t s_reg_32 = or_register_32_imm32(0xcd00);
  uint64_t s_rax_32 = or_implicit_rax_imm32(0xcd00abcdef);
  uint64_t s_reg_64_i8 = or_register_64_imm8(0xcd00abcdef);
  uint64_t s_reg_64_i32 = or_register_64_imm32(0xcd00abcdef);
  return 0;
}
