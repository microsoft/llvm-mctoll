// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Expect: 18 

#include <stdio.h>
int fooA(int, int);
int fooB(int, int);
int fooC(int);
int fooD(int, int, int, int);
int fooE(int);

int __attribute__((noinline)) fooA(int a, int b) {
  return fooB(a, fooD(a, b, a, b));
}

int __attribute__((noinline)) fooB(int a, int b) {
  int r = 0;
  r = a + b;
  r = fooD(r, a, b, r);
  return fooC(r);
}

int __attribute__((noinline)) fooC(int a) {
  int r = 0;
  r = a + 1;
  printf("fooC return: %d\n", r);

  return r;
}

int __attribute__((noinline)) fooD(int a, int b, int c, int d) {
  return fooE(fooC(fooE(a))) + c + d;
}

int __attribute__((noinline)) fooE(int a) {
  int r = 0;
  if (a < 2) {
    r = fooE(a + 1);
  }

  return r;
}

int main() {
  int x = 3;
  int y = 4;
  int z = fooA(x, y);
  printf("Expect: %d\n", z);
  return 0;
}

