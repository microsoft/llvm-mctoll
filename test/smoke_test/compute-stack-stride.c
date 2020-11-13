// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d --include-files="/usr/include/stdio.h,/usr/include/stdlib.h,/usr/include/string.h" %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
//CHECK:arr3[1] = -127
//CHECK:arr3[2] = -126
//CHECK:arr3[3] = -125
//CHECK:arr3[4] = -124
//CHECK:arr3[0] = -128, arr3[1] = -127, arr3[2] = -126, arr3[3] = -125, arr3[4] = -124

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

int __attribute__((noinline))
foo(char *a3, const int num) {
  for (int i = 0; i < num; i++) {
    a3[i] = CHAR_MIN + i;
  }
  return 0;
}

int main() {
  const int num = 5;
  char *arr3 = (char *) calloc(num, sizeof(int));

  foo(arr3, num);

  if (arr3[0] > 0)
    printf("arr3[0] = %hhd\n", arr3[0]);
  printf("arr3[1] = %hhd\n", arr3[1]);
  printf("arr3[2] = %hhd\n", arr3[2]);
  printf("arr3[3] = %hhd\n", arr3[3]);
  printf("arr3[4] = %hhd\n", arr3[4]);
  printf("arr3[0] = %hhd, arr3[1] = %hhd, arr3[2] = %hhd, arr3[3] = %hhd, "
         "arr3[4] = %hhd\n", arr3[0], arr3[1], arr3[2], arr3[3], arr3[4]);

  return 0;
}
