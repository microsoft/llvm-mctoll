// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: [Implicit AX/DX]
// CHECK-NEXT: Test 0xf1d2 DIV16m 0xf123
// CHECK-NEXT: Quotient = 0x1, Remainder = 0xaf
// CHECK-NEXT: [Implicit EAX/EDX]
// CHECK-NEXT: Test 0x9feeddcc DIV32m 0xf8
// CHECK-NEXT: Quotient = 0xa5179a, Remainder = 0x9c
// CHECK-NEXT: [Implicit RAX/RDX]
// CHECK-NEXT: Test 0xbbaaccdd12345678 DIV64m 0xabcdef
// CHECK-NEXT: Quotient = 0x117a2f5f875, Remainder = 0x74b03d
// CHECK-EMPTY
#include <stdio.h>

// DIV16m $rbp, 1, $noreg, -24, $noreg, <0x4ce82d8>, implicit-def $ax,
// implicit-def $dx, implicit-def $eflags, implicit $ax, implicit $dx
unsigned short __attribute__((noinline))
test_divm16_ax_dx(unsigned short a, unsigned short b) {
  unsigned short quotient = 0;
  unsigned short remainder = 0;

  printf("[Implicit AX/DX]\nTest 0x%x DIV16m 0x%x\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movw  %2, -4(%%rbp)\n"
      "movq  %%rsi, -16(%%rbp)\n"
      "movw  %%dx, -18(%%rbp)\n"
      "movw  %3, -24(%%rbp)\n"
      "movw  -4(%%rbp), %%ax\n"
      "xorw  %%dx, %%dx\n"
      "divw  -24(%%rbp)\n"
      "movw  %%ax, %0\n"
      "movw  %%dx, %1\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(quotient), "=r"(remainder)      /* output operands */
      : "r"(a), "r"(b)                       /* input operands */
      : "%ax", "%dx", "%rbp", "%rsp", "%rsi" /* list of clobbered registers */
  );

  printf("Quotient = 0x%x, Remainder = 0x%x\n", quotient, remainder);
  return 0;
}

// DIV32m $rbp, 1, $noreg, -24, $noreg, <0x52e61b8>, implicit-def $eax,
// implicit-def $edx, implicit-def $eflags, implicit $eax, implicit $edx
unsigned int __attribute__((noinline))
test_divm32_eax_edx(unsigned int a, unsigned int b) {
  unsigned int quotient = 0;
  unsigned int remainder = 0;

  printf("[Implicit EAX/EDX]\nTest 0x%x DIV32m 0x%x\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movl  %2, -4(%%rbp)\n"
      "movq  %%rsi, -16(%%rbp)\n"
      "movw  %%dx, -18(%%rbp)\n"
      "movl  %3, -24(%%rbp)\n"
      "movl  -4(%%rbp), %%eax\n"
      "xorl  %%edx, %%edx\n"
      "divl  -24(%%rbp)\n"
      "movl  %%eax, %0\n"
      "movl  %%edx, %1\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(quotient), "=r"(remainder)        /* output operands */
      : "r"(a), "r"(b)                         /* input operands */
      : "%eax", "%edx", "%rbp", "%rsp", "%rsi" /* list of clobbered registers */
  );

  printf("Quotient = 0x%x, Remainder = 0x%x\n", quotient, remainder);
  return 0;
}

// DIV64m $rbp, 1, $noreg, -28, $noreg, <0x4b06518>, implicit-def $rax,
// implicit-def $rdx, implicit-def $eflags, implicit $rax, implicit $rdx
unsigned long int __attribute__((noinline))
test_divm64_rax_rdx(unsigned long int a, unsigned long int b) {
  unsigned long int quotient = 0;
  unsigned long int remainder = 0;

  printf("[Implicit RAX/RDX]\nTest 0x%lx DIV64m 0x%lx\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movq  %2, -8(%%rbp)\n"
      "movq  %%rsi, -16(%%rbp)\n"
      "movl  %%edx, -20(%%rbp)\n"
      "movq  %3, -28(%%rbp)\n"
      "movq  -8(%%rbp), %%rax\n"
      "xorq  %%rdx, %%rdx\n"
      "divq  -28(%%rbp)\n"
      "movq  %%rax, %0\n"
      "movq  %%rdx, %1\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(quotient), "=r"(remainder)        /* output operands */
      : "r"(a), "r"(b)                         /* input operands */
      : "%rax", "%rdx", "%rbp", "%rsp", "%rsi" /* list of clobbered registers */
  );

  printf("Quotient = 0x%lx, Remainder = 0x%lx\n", quotient, remainder);
  return 0;
}

int main() {
  test_divm16_ax_dx(0xF1D2, 0xF123);

  test_divm32_eax_edx(0x9FEEDDCC, 0xF8);

  test_divm64_rax_rdx(0xBBAACCDD12345678, 0xABCDEF);
  return 0;
}
