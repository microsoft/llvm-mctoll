// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Value a 5
// CHECK: Value b 6
// CHECK: Value a 4
// CHECK: Value b 2

/* When compiled with -O2, the generated code follows a pattern that
   requires reaching definition analysis and storing of certain values
   to stack to faciliate merged use in later blocks.
 */
#include <stdio.h>
void __attribute__ ((noinline))  call_func(int i, int j) {
  int a = 0;
  int b = 0;
  if (j < 0) {
    a = 4;
    b = 2;
  } else {
    a = i / j;
    b = 6;
  }
  printf("Value a %d\n", a);
  printf("Value b %d\n", b);
  return;
}

int main(int argc, char **argv) {
  call_func(10,2);
  call_func(10,-1);
  return 0;
}
