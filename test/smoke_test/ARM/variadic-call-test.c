// RUN: clang -o %t.o %s --target=%arm_triple
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Hello, World!
// CHECK: Hello again, World!
// CHECK: Sum = 6912
// CHECK: Sum of 1234 and 5678 = 6912

#include <stdio.h>

int main() {
  int a = 1234, b = 5678;
  printf("Hello, World!\n");
  printf("Hello again, World!\n");
  printf("Sum = %d\n", a + b);
  printf("Sum of %d and %d = %d\n", a, b, a + b);
}
