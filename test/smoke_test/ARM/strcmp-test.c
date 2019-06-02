// RUN: clang %S/../Inputs/strcmp.c -o %t.so --target=%arm_triple -shared -fPIC
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll -mx32
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Lesser
// CHECK-NEXT: Equal
// CHECK-NEXT: Greater

#include <stdio.h>

extern int libc_strcmp(const char *p1, const char *p2);

int main() {
  const char s1[] = "This is a string with label AOne";
  const char s2[] = "This is a string with label ATwo";

  int val = libc_strcmp(s1, s2);

  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  val = libc_strcmp(s2, s2);
  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  val = libc_strcmp(s2, s1);
  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  return 0;
}
