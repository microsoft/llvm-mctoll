// This test is disabled till work resumes on support for
// raising ARM binaries to catch-up with that for x64 binaries.
// UNSUPPORTED: -linux-
// RUN: clang %S/../Inputs/switch_func.c -o %t.so --target=%arm_triple -fuse-ld=lld -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Switch 1
// CHECK-NEXT: Return 15
// CHECK-NEXT: Switch 2
// CHECK-NEXT: Return 17
// CHECK-NEXT: Switch 3
// CHECK-NEXT: Return 18
// CHECK-NEXT: Switch 4
// CHECK-NEXT: Return 14
// CHECK-NEXT: Switch 5
// CHECK-NEXT: Return 16
// CHECK-NEXT: Switch 6
// CHECK-NEXT: Return 18
// CHECK-NEXT: Switch 7
// CHECK-NEXT: Return 22
// CHECK-NEXT: Switch 8
// CHECK-NEXT: Return 23
// CHECK-NEXT: Switch 9
// CHECK-NEXT: Return 22

#include <stdio.h>
#include <stdlib.h>

extern int switch_test(int);

int main(int argc, char** argv) {
  int n = 0;

  if (argc > 1) {
    n = atoi(argv[1]);
    printf("Return %d\n", switch_test(n));
  }
  else {
    for (int n = 1; n < 10; n++) {
      printf("Switch %d\n", n);
      printf("Return %d\n", switch_test(n));
    }
  }

  return 0;
}
