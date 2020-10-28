// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: EDCBA

#include <stdio.h>

int __attribute__((noinline)) display_backward(char *string) {
  if (*string) {
    display_backward(string + 1);
    putchar(*string);
  }
  return 0;
}

int main(void) {
  display_backward("ABCDE");
  printf("\n");
  return 0;
}
