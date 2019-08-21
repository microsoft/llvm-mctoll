// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: retval: 0
// CHECK: retval: 2
// CHECK: retval: 5
// CHECK: retval: 32
// CHECK: ret: 32

#include <stdio.h>

int __attribute__((noinline)) parseval(char *valstring) {
  int retval = 0;
  while ((*valstring >= '0')) {
    int digit = *valstring - '0';
    retval += digit;
    printf("retval: %d\n", retval);
    valstring++;
  }
  return retval;
}

int main(int argc, char **argv) {
  char *str = "023K";
  int ret = parseval(str);
  printf("ret: %d\n", ret);
  return 0;
}
