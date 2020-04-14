// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:a[0] = 4, a[1] = 5, a[2] = 6, a[3] = 7, a[4] = 8
// CHECK:arr[0] = 4, arr[1] = 5, arr[2] = 6, arr[3] = 7, arr[4] = 8
// CHECK:Help Print Info: i = 10, j = 11, k = 12, l = 13, m = 13

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
  int i = 9, j = 10, k = 11, l = 12, m = 13;
  int arr[5] = {0};

  foo(arr);
 
  i = j;
  j = k;
  k = l;
  l = m;

  printf("arr[0] = %d, arr[1] = %d, arr[2] = %d, arr[3] = %d, arr[4] = %d\n", arr[0], arr[1], arr[2], arr[3], arr[4]);
  printf("Help Print Info: i = %d, j = %d, k = %d, l = %d, m = %d\n",  i, j, k, l, m);
  return 0;
}
