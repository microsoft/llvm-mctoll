// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Value : 0xffff
// CHECK: Not of Value : 0xffff0000
// CHECK: Changed Value : 0xffff0000

#include <stdio.h>
__attribute__((noinline)) void call_me_ref(int *a) {
  *a = ~(*a);
  return;
}

__attribute__((noinline)) int call_me_val(int a) { return ~a; }

int main(int argc, char **argv) {
  int v = 0xffff;
  printf("Value : 0x%x\n", v);
  printf("Not of Value : 0x%x\n", call_me_val(v));
  call_me_ref(&v);
  printf("Changed Value : 0x%x\n", v);
  return 0;
}
