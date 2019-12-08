// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: result before SHL f
// CHECK: result after SHL ff

#include <stdio.h>
typedef unsigned short ee_s16;
int main(int argc, char **argv) {
  ee_s16 dtype = 0xf;
  printf("result before SHL %x \n", dtype);
  dtype |= dtype << 4;
  printf("result after SHL %x \n", dtype);
  return 0;
}
