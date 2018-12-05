// RUN: clang -o %t -O2 %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Val before increment 41
// CHECK: Modified Val in func call 42
// CHECK: Val after increment 42

/* Code to test correct handling of
    a) directly dereferenced argument value
    b) tail-call converted to jmp.
    c) empty basic block deletion
*/
#include <stdio.h>

void incr(int *v) {
  (*v)++;
  // Higher opt level will convert this tail call to a jmp
  printf("Modified Val in func call %d\n", *v);
}

int main() {
  int val = 41;
  printf("Val before increment %d\n", val);
  incr(&val);
  printf("Val after increment %d\n", val);
}
