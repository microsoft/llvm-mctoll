// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:a[0] = 4, a[1] = 5, a[2] = 6, a[3] = 7, a[4] = 8
// CHECK:arr[0] = 4
// CHECK:arr[1] = 5
// CHECK:arr[2] = 6
// CHECK:arr[3] = 7
// CHECK:arr[4] = 8
// CHECK:arr[0] = 4, arr[1] = 5, arr[2] = 6, arr[3] = 7, arr[4] = 8

#include <stdio.h>

int __attribute__((noinline))foo(int *a)
{
  a[0] = 4;
  a[1] = 5;
  a[2] = 6;
  a[3] = 7;
  a[4] = 8;
  printf("a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d, a[4] = %d\n", a[0], a[1], a[2], a[3], a[4]);
  return 0;
}

int main()
{
  int arr[5] = {0};
  foo(arr);

  if (arr[0] > 3)
    printf("arr[0] = %d\n", arr[0]);
  if (arr[1] > 4)
    printf("arr[1] = %d\n", arr[1]);
  if (arr[2] > 5)
    printf("arr[2] = %d\n", arr[2]);
  if (arr[3] > 6)
    printf("arr[3] = %d\n", arr[3]);
  if (arr[4] > 7)
    printf("arr[4] = %d\n", arr[4]);
  printf("arr[0] = %d, arr[1] = %d, arr[2] = %d, arr[3] = %d, arr[4] = %d\n", arr[0], arr[1], arr[2], arr[3], arr[4]);
  return 0;
}
