// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0 0 0 0 0 0 0 0 0 0

#include <stdio.h>
#include <string.h>
int main(void) {
  int i;
  char str[10];
  char *p = str;
  memset(str, 0, sizeof(str));
  for (i = 0; i < 10; ++i) {
    printf("%d\x20", str[i]);
  }
  printf("\n");
  return 0;
}
