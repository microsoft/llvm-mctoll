// REQUIRES: system-linux
// XFAIL: x86_64
// RUN: clang -c %s -o %t
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t 2>&1 | FileCheck %s
// CHECK: Raising x64 relocatable (.o) x64 binaries not supported

#include <stdio.h>
int main(int argc, char **argv) {
  printf("Hello world!\n");
  return 0;
}
