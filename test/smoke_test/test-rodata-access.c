// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: str: test ok!

/* The binary of this test contains a mov instruction that references .rodata
 * section address. Such an address needs to be recognized and abstracted
 * correctly.
 */
#include <stdio.h>

void __attribute__((noinline)) call_test(char **instr) {
  char *str = *instr;
  printf("str: %s\n", str);
}

int main(int argc, char **argv) {
  char *instr = "test ok!";
  call_test(&instr);
  return 0;
}
