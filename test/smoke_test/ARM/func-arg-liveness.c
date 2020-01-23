// RUN: clang -o %t %s -O2 --target=%arm_triple -fuse-ld=lld
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Value 12
// CHECK: Value 4

/* Compiling this test with -O2 generates code with no prolog
   and use of first argument occurs in a basic block other than
   the first. This tests detection of argument register usage
   anywhere in the CFG
*/

#include <stdio.h>

void call_me(int i, int j) {
  int a;
  if (j  == 0) {
    a = 4;
  } else {
    a = i + j;
  }
  printf("Value %d\n", a);
  return;
}

int main(int argc, char **argv) {
  call_me(10,2);
  call_me(10,0);
  return 0;
}
