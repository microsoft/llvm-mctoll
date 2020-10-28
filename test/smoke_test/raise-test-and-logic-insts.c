// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: result: 44801

/*
 * This test will produce the mi as follows:
 * TEST8ri $sil, 1, <0x562e17bc9028>, implicit-def $eflags
 * TEST8i8 1, <0x562e17bc3778>, implicit-def $eflags, implicit $al
 * CMP8rr $dil, $cl, <0x562e17bcc958>, implicit-def $eflags
 * $dl = XOR8rr $dl(tied-def 0), $cl, <0x562e17bc3ad8>, implicit-def $eflags
 * $cl = SHR8ri $cl(tied-def 0), 2, <0x562e17bc4d28>, implicit-def $eflags
 * $cl = SHR8r1 $cl(tied-def 0), <0x562e17bc32f8>, implicit-def $eflags
 */

#include <stdio.h>

unsigned short __attribute__((noinline))
call_func(unsigned char data, unsigned short arg) {
  unsigned char i = 0, x16 = 0, carry = 0;
  for (i = 0; i < 8; i++) {
    x16 = (unsigned char)((data & 1) ^ ((unsigned char)arg & 1));
    data >>= 1;

    if (x16 == 1) {
      arg ^= 0x4002;
      carry = 1;
    } else
      carry = 0;
    arg >>= 1;
    if (carry)
      arg |= 0x8000;
    else
      arg &= 0x7fff;
  }
  return arg;
}

int main() {
  unsigned short data = 0x0102;
  unsigned short arg = 0x96;
  unsigned short result = call_func((unsigned char)data, arg);
  printf("result: %d \n", result);
  return 0;
}
