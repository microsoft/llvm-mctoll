// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: r1: 9
// CHECK: r2: 8

/*
 * This test will produce the mi as follows:
 * JMP_1 -39, <0x556ee5f3fd28>
 */

#include<stdio.h>

int __attribute__((noinline)) foo2(int a , int b) {
  return a + b;
}

int __attribute__((noinline)) foo1(int a , int b) {
  return foo2(a, b);
}

int __attribute__((noinline)) foo3(int a)  {
  int b = 5;
  int c = foo2(a, b);
  return c;
}

int main() {
  int A = 3;
  int B = 6;
  int r1 = foo1(A, B);
  printf(" r1: %d \n", r1);
  int r2 = foo3(A);
  printf(" r2: %d \n", r2);
  return 0;
}
