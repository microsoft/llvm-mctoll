// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/globalvar.c -shared -fPIC
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: GlobalVar Initial value = 42
// CHECK-NEXT: myglobal_func returns 72
// CHECK-NEXT: GlobalVar updated value = 52

#include <stdio.h>

extern int myglob;
extern int myglobal_func(int a, int b);

int main() {
  printf("GlobalVar Initial value = %d\n", myglob);
  printf("myglobal_func returns %d\n", myglobal_func(10, 20));
  printf("GlobalVar updated value = %d\n", myglob);
  return 0;
}
