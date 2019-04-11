// RUN: clang -o %t.o %s -c -mx32 -target armv4t -mfloat-abi=soft
// RUN: arm-none-linux-gnueabi-gcc %t.o -o %t
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Hello world!

#include <stdio.h>
int main(int argc, char **argv) {
  printf("Hello world!\n");
  return 0;
}
