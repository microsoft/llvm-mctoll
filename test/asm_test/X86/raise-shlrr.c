// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Test SHL8rCL 0x21 by 4
// CHECK-NEXT: Result : 0x10
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL8rCL 0xf1 by 4
// CHECK-NEXT: Result : 0x10
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL8rCL 0x1f by 4
// CHECK-NEXT: Result : 0xf0
// CHECK-NEXT:  Flags: CF = 1 SF = 1 ZF = 0
// CHECK-NEXT: Test SHL8rCL 0x10 by 4
// CHECK-NEXT: Result : 0x0
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 1
// CHECK-NEXT: Test SHL16rCL 0x2100 by 4
// CHECK-NEXT: Result : 0x1000
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL16rCL 0xf100 by 4
// CHECK-NEXT: Result : 0x1000
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL16rCL 0x1f00 by 4
// CHECK-NEXT: Result : 0xf000
// CHECK-NEXT:  Flags: CF = 1 SF = 1 ZF = 0
// CHECK-NEXT: Test SHL16rCL 0x1000 by 4
// CHECK-NEXT: Result : 0x0
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 1
// CHECK-NEXT: Test SHL32rCL 0x21000000 by 4
// CHECK-NEXT: Result : 0x10000000
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL32rCL 0xf1000000 by 4
// CHECK-NEXT: Result : 0x10000000
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL32rCL 0x1f000000 by 4
// CHECK-NEXT: Result : 0xf0000000
// CHECK-NEXT:  Flags: CF = 1 SF = 1 ZF = 0
// CHECK-NEXT: Test SHL32rCL 0x10000000 by 4
// CHECK-NEXT: Result : 0x0
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 1
// CHECK-NEXT: Test SHL32rCL 0x1 by 34
// CHECK-NEXT: Result : 0x4
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL64rCL 0x2100000000000000 by 4
// CHECK-NEXT: Result : 0x1000000000000000
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL64rCL 0xf100000000000000 by 4
// CHECK-NEXT: Result : 0x1000000000000000
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 0
// CHECK-NEXT: Test SHL64rCL 0x1f00000000000000 by 4
// CHECK-NEXT: Result : 0xf000000000000000
// CHECK-NEXT:  Flags: CF = 1 SF = 1 ZF = 0
// CHECK-NEXT: Test SHL64rCL 0x1000000000000000 by 4
// CHECK-NEXT: Result : 0x0
// CHECK-NEXT:  Flags: CF = 1 SF = 0 ZF = 1
// CHECK-NEXT: Test SHL64rCL 0x1000000000000001 by 66
// CHECK-NEXT: Result : 0x4000000000000004
// CHECK-NEXT:  Flags: CF = 0 SF = 0 ZF = 0
// CHECK-EMPTY:

#include "stdint.h"
#include "stdio.h"

// Compute shl of reg value and implicit cl
// SHL8rCL
uint8_t __attribute__((noinline)) shl8_reg_implicit_cl(uint8_t val, uint8_t count) {
  uint8_t result;
  uint8_t cf, zf, sf;
  printf("Test SHL8rCL 0x%x by %hd\n", val, count);
  __asm__("mov %4, %%al \n"
	  "mov %5, %%cl \n"
	  "shl %%cl, %%al\n"
	  "setc %%bl\n"
	  "sets %%cl\n"
	  "setz %%dl\n"
	  "mov %%al, %0 \n"
	  "mov %%bl, %1 \n"
	  "mov %%cl, %2 \n"
	  "mov %%dl, %3 \n"
	  : "=r"(result) , "=r"(cf), "=r"(sf), "=r"(zf)              /* output */
	  : "r"(val), "r"(count)           /* input */
	  : "%al", "%cl", "%bl", "%dl"       /* clobbered register */
	  );
  printf("Result : 0x%x\n Flags: CF = %hd SF = %hd ZF = %hd\n", result, cf, sf, zf);
  return result;
}

// Compute shl of reg value and implicit cl
// SHL16rCL
uint16_t __attribute__((noinline)) shl16_reg_implicit_cl(uint16_t val, uint8_t count) {
  uint16_t result;
  uint8_t cf, zf, sf;
  printf("Test SHL16rCL 0x%x by %hd\n", val, count);
  __asm__("mov %4, %%ax \n"
	  "mov %5, %%cl \n"
	  "shl %%cl, %%ax\n"
	  "setc %%bl\n"
	  "sets %%cl\n"
	  "setz %%dl\n"
	  "mov %%ax, %0 \n"
	  "mov %%bl, %1 \n"
	  "mov %%cl, %2 \n"
	  "mov %%dl, %3 \n"
	  : "=r"(result) , "=r"(cf), "=r"(sf), "=r"(zf)              /* output */
	  : "r"(val), "r"(count)           /* input */
	  : "%ax", "%cx", "%bl", "%dl"       /* clobbered register */
	  );
  printf("Result : 0x%x\n Flags: CF = %hd SF = %hd ZF = %hd\n", result, cf, sf, zf);
  return result;
}

// Compute shl of reg value and implicit cl
// SHL32rCL
uint32_t __attribute__((noinline)) shl32_reg_implicit_cl(uint32_t val, uint8_t count) {
  uint32_t result;
  uint8_t cf, zf, sf;
  printf("Test SHL32rCL 0x%x by %hd\n", val, count);
  __asm__("mov %4, %%eax \n"
	  "mov %5, %%cl \n"
	  "shl %%cl, %%eax\n"
	  "setc %%bl\n"
	  "sets %%cl\n"
	  "setz %%dl\n"
	  "mov %%eax, %0 \n"
	  "mov %%bl, %1 \n"
	  "mov %%cl, %2 \n"
	  "mov %%dl, %3 \n"
	  : "=r"(result) , "=r"(cf), "=r"(sf), "=r"(zf)              /* output */
	  : "r"(val), "r"(count)           /* input */
	  : "%eax", "%ecx", "%bl", "%dl"       /* clobbered register */
	  );
  printf("Result : 0x%x\n Flags: CF = %hd SF = %hd ZF = %hd\n", result, cf, sf, zf);
  return result;
}

// Compute shl of reg value and implicit cl
// SHL64rCL
uint64_t __attribute__((noinline)) shl64_reg_implicit_cl(uint64_t val, uint8_t count) {
  uint64_t result;
  uint8_t cf, zf, sf;
  printf("Test SHL64rCL 0x%lx by %hd\n", val, count);
  __asm__("mov %4, %%rax \n"
	  "mov %5, %%cl \n"
	  "shl %%cl, %%rax\n"
	  "setc %%bl\n"
	  "sets %%cl\n"
	  "setz %%dl\n"
	  "mov %%rax, %0 \n"
	  "mov %%bl, %1 \n"
	  "mov %%cl, %2 \n"
	  "mov %%dl, %3 \n"
	  : "=r"(result) , "=r"(cf), "=r"(sf), "=r"(zf)              /* output */
	  : "r"(val), "r"(count)           /* input */
	  : "%rax", "%rcx", "%bl", "%dl"       /* clobbered register */
	  );
  printf("Result : 0x%lx\n Flags: CF = %hd SF = %hd ZF = %hd\n", result, cf, sf, zf);
  return result;
}

// Test raising of various flavors of shl instruction
int main() {
  uint8_t s_8 = shl8_reg_implicit_cl(0x21, 4);
  s_8 = shl8_reg_implicit_cl(0xf1, 4);
  s_8 = shl8_reg_implicit_cl(0x1f, 4);
  s_8 = shl8_reg_implicit_cl(0x10, 4);

  uint16_t s_16 = shl16_reg_implicit_cl(0x2100, 4);
  s_16 = shl16_reg_implicit_cl(0xf100, 4);
  s_16 = shl16_reg_implicit_cl(0x1f00, 4);
  s_16 = shl16_reg_implicit_cl(0x1000, 4);

  uint32_t s_32 = shl32_reg_implicit_cl(0x21000000, 4);
  s_32 = shl32_reg_implicit_cl(0xf1000000, 4);
  s_32 = shl32_reg_implicit_cl(0x1f000000, 4);
  s_32 = shl32_reg_implicit_cl(0x10000000, 4);
  s_32 = shl32_reg_implicit_cl(0x1, 34);

  uint64_t s_64 = shl64_reg_implicit_cl(0x2100000000000000, 4);
  s_64 = shl64_reg_implicit_cl(0xf100000000000000, 4);
  s_64 = shl64_reg_implicit_cl(0x1f00000000000000, 4);
  s_64 = shl64_reg_implicit_cl(0x1000000000000000, 4);
  s_64 = shl64_reg_implicit_cl(0x1000000000000001, 66);

  return 0;
}
