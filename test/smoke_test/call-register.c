// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: call_test val: 8
// CHECK: call_test val: 9

#include <stdio.h>

typedef int(*call_me)(int a, int b);

int __attribute__((noinline)) func_test(int a, int b) {
  return (a > b) ? a : b;
}

int __attribute__((noinline)) val_test(int a, int b) {
  return (a < b) ? (a + b) : (a - b);
}

int __attribute__((noinline)) call_test(int a, call_me func_ptr) {
  int v = 0;
  if (a > 5) {
    v = a + 211;
  }  else {
    v = a - (191+a)/32;
  }

  int ret = func_ptr(v, 4);
  return a + ret;
}

int main(int argc, char **argv) {
  int ret = 0;
  ret = call_test(5, val_test);
  printf("call_test val: %d\n", ret);
  ret = call_test(5, func_test);
  printf("call_test val: %d\n", ret);

  return 0;
}
