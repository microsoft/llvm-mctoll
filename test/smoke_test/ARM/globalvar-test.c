// RUN: clang %S/../Inputs/globalvar.c -o %t.so --target=%arm_triple -shared
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll -mx32
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
