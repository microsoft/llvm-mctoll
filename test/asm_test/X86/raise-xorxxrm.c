// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Test 0xff XOR8rm 0xaa
// CHECK-NEXT: Result : 0x55
// CHECK-NEXT: Flags: OF = 0, CF = 0, SF = 0, ZF = 0
// CHECK-NEXT: Test 0xa9b4 XOR16rm 0xf825
// CHECK-NEXT: Result : 0x5191
// CHECK-NEXT: Flags: OF = 0, CF = 0, SF = 0, ZF = 0
// CHECK-NEXT: Test 0x9feeddcc XOR32rm 0x60223344
// CHECK-NEXT: Result : 0xffccee88
// CHECK-NEXT: Flags: OF = 0, CF = 0, SF = 1, ZF = 0
// CHECK-NEXT: Test 0x9baaccdd12345678 XOR64rm 0xabcdef
// CHECK-NEXT: Result : 0x9baaccdd129f9b97
// CHECK-NEXT: Flags: OF = 0, CF = 0, SF = 1, ZF = 0
// CHECK-EMPTY
#include <stdio.h>

// $al = XOR8rm $al(tied-def 0), $rbp, 1, $noreg, -24, $noreg, <0x56981c8>,
// implicit-def $eflags
unsigned char __attribute__((noinline))
test_xor8rm_al(unsigned char a, unsigned char b) {
  unsigned char result = 0;
  unsigned char of, cf, sf, zf;

  printf("Test 0x%x XOR8rm 0x%x\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movb  %5, %%al\n"
      "mov   %%rsi, -16(%%rbp)\n"
      "movb  %6, -24(%%rbp)\n"
      "xorb  -24(%%rbp), %%al\n"
      "seto  %%bl\n"
      "setc  %%cl\n"
      "sets  %%dl\n"
      "setz  %%r8b\n"
      "mov   %%al, %0\n"
      "mov   %%bl, %1\n"
      "mov   %%cl, %2\n"
      "mov   %%dl, %3\n"
      "mov   %%r8b, %4\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(result), "=r"(of), "=r"(cf), "=r"(sf),
        "=r"(zf)                           /* output operands */
      : "r"(a), "r"(b)                     /* input operands */
      : "%al", "%bl", "%cl", "%dl", "%r8b" /* list of clobbered registers */
  );

  printf("Result : 0x%x\nFlags: OF = %hd, CF = %hd, SF = %hd, ZF = %hd\n",
         result, of, cf, sf, zf);
  return 0;
}

// $ax = XOR16rm $ax(tied-def 0), $rbp, 1, $noreg, -24, $noreg, <0x4ab9d38>,
// implicit-def $eflags
unsigned short __attribute__((noinline))
test_xor16rm_ax(unsigned short a, unsigned short b) {
  unsigned short result = 0;
  unsigned char of, cf, sf, zf;

  printf("Test 0x%x XOR16rm 0x%x\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "mov  %5, -4(%%rbp)\n"
      "mov  %%rsi, -16(%%rbp)\n"
      "mov   %6, -24(%%rbp)\n"
      "mov   -4(%%rbp), %%ax\n"
      "xor   -24(%%rbp), %%ax\n"
      "seto  %%bl\n"
      "setc  %%cl\n"
      "sets  %%dl\n"
      "setz  %%r8b\n"
      "mov   %%ax, %0\n"
      "mov   %%bl, %1\n"
      "mov   %%cl, %2\n"
      "mov   %%dl, %3\n"
      "mov   %%r8b, %4\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(result), "=r"(of), "=r"(cf), "=r"(sf),
        "=r"(zf)                           /* output operands */
      : "r"(a), "r"(b)                     /* input operands */
      : "%ax", "%bl", "%cl", "%dl", "%r8b" /* list of clobbered registers */
  );

  printf("Result : 0x%x\nFlags: OF = %hd, CF = %hd, SF = %hd, ZF = %hd\n",
         result, of, cf, sf, zf);
  return 0;
}

// $eax = XOR32rm $eax(tied-def 0), $rbp, 1, $noreg, -60, $noreg, <0x441cc88>,
// implicit-def $eflags
unsigned int __attribute__((noinline))
test_xor32rm_eax(unsigned int a, unsigned int b) {
  unsigned int result = 0;
  unsigned char of, cf, sf, zf;

  printf("Test 0x%x XOR32rm 0x%x\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movl  %5, -4(%%rbp)\n"
      "movq  %%rsi, -16(%%rbp)\n"
      "movw  %%dx, -18(%%rbp)\n"
      "movl  %6, -24(%%rbp)\n"
      "movl  -4(%%rbp), %%eax\n"
      "xorl  -24(%%rbp), %%eax\n"
      "seto  %%bl\n"
      "setc  %%cl\n"
      "sets  %%dl\n"
      "setz  %%r8b\n"
      "movl  %%eax, %0\n"
      "mov   %%bl, %1\n"
      "mov   %%cl, %2\n"
      "mov   %%dl, %3\n"
      "mov   %%r8b, %4\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(result), "=r"(of), "=r"(cf), "=r"(sf),
        "=r"(zf)                            /* output operands */
      : "r"(a), "r"(b)                      /* input operands */
      : "%eax", "%bl", "%cl", "%dl", "%r8b" /* list of clobbered registers */
  );

  printf("Result : 0x%x\nFlags: OF = %hd, CF = %hd, SF = %hd, ZF = %hd\n",
         result, of, cf, sf, zf);
  return 0;
}

// $rax = XOR64rm $rax(tied-def 0), $rbp, 1, $noreg, -32, $noreg, <0x5effa48>,
// implicit-def $eflags
unsigned long int __attribute__((noinline))
test_xor64rm_rax(unsigned long int a, unsigned long int b) {
  unsigned long int result = 0;
  unsigned char of, cf, sf, zf;

  printf("Test 0x%lx XOR64rm 0x%lx\n", a, b);

  asm("pushq %%rbp\n"
      "movq  %%rsp, %%rbp\n"
      "subq  $112, %%rsp\n"
      "movq  %5, -8(%%rbp)\n"
      "movq  %%rsi, -16(%%rbp)\n"
      "movl  %%edx, -20(%%rbp)\n"
      "movq  %6, -32(%%rbp)\n"
      "movq  -8(%%rbp), %%rax\n"
      "xorq  -32(%%rbp), %%rax\n"
      "seto  %%bl\n"
      "setc  %%cl\n"
      "sets  %%dl\n"
      "setz  %%r8b\n"
      "movq  %%rax, %0\n"
      "mov   %%bl, %1\n"
      "mov   %%cl, %2\n"
      "mov   %%dl, %3\n"
      "mov   %%r8b, %4\n"
      "addq  $112, %%rsp\n"
      "popq  %%rbp\n"
      : "=r"(result), "=r"(of), "=r"(cf), "=r"(sf),
        "=r"(zf)                            /* output operands */
      : "r"(a), "r"(b)                      /* input operands */
      : "%rax", "%bl", "%cl", "%dl", "%r8b" /* list of clobbered registers */
  );

  printf("Result : 0x%lx\nFlags: OF = %hd, CF = %hd, SF = %hd, ZF = %hd\n",
         result, of, cf, sf, zf);
  return 0;
}

int main() {
  test_xor8rm_al(0xFF, 0xAA);
  test_xor16rm_ax(0xA9B4, 0xF825);
  test_xor32rm_eax(0x9FEEDDCC, 0x60223344);
  test_xor64rm_rax(0x9BAACCDD12345678, 0xABCDEF);
  return 0;
}
