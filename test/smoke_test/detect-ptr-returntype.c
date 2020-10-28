// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/string.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Check external function return type is pointer!
// CHECK: $$$$$$$$$ernal function return type is pointer!
#include <stdio.h>
#include <string.h>

char str[50];
void __attribute__((noinline)) foo() {
  strcpy(str, "Check external function return type is pointer!");
  puts(str);

  memset(str, '$', 9);
}

int main() {
  foo();
  puts(str);
  return 0;
}
