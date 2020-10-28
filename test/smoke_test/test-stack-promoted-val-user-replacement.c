// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:arr[0] = 2147483647, arr[1] = 2147483646, arr[2] = 2147483645, arr[3] = 2147483644, arr[4] = 2147483643 
// CHECK:arr1[0] = 4294967295, arr1[1] = 4294967294, arr1[2] = 4294967293, arr1[3] = 4294967292, arr1[4] = 4294967291
// CHECK:arr2[0] = -32768, arr2[1] = -32767, arr2[2] = -32766, arr2[3] = -32765, arr2[4] = -32764
// CHECK:arr3[0] = -128, arr3[1] = -127, arr3[2] = -126, arr3[3] = -125, arr3[4] = -124 
// CHECK:arr4[0] = -9223372036854775808, arr4[1] = -9223372036854775807, arr4[2] = -9223372036854775806, arr4[3] = -9223372036854775805, arr4[4] = -9223372036854775804

#include <limits.h>
#include <stdio.h>

int __attribute__((noinline))
foo(int *a, unsigned int *a1, short *a2, char *a3, long *a4, const int num) {
  for (int i = 0; i < num; i++) {
    a[i] = INT_MAX - i;
    a1[i] = UINT_MAX - i;
    a2[i] = SHRT_MIN + i;
    a3[i] = CHAR_MIN + i;
    a4[i] = LONG_MIN + i;
  }
  return 0;
}

int main() {
  const int num = 5;
  int arr[num] = {0};
  unsigned int arr1[num] = {0};
  short arr2[num] = {0};
  char arr3[num] = {0};
  long arr4[num] = {0};

  foo(arr, arr1, arr2, arr3, arr4, num);

  if (arr[0] > 10)
    printf("arr[0] = %d, arr[1] = %d, arr[2] = %d, arr[3] = %d, arr[4] = %d\n",
           arr[0], arr[1], arr[2], arr[3], arr[4]);
  printf("arr1[0] = %u, arr1[1] = %u, arr1[2] = %u, arr1[3] = %u, arr1[4] = %u\n",
         arr1[0], arr1[1], arr1[2], arr1[3], arr1[4]);
  printf("arr2[0] = %hd, arr2[1] = %hd, arr2[2] = %hd, arr2[3] = %hd, arr2[4] "
         "= %hd\n", arr2[0], arr2[1], arr2[2], arr2[3], arr2[4]);
  printf("arr3[0] = %hhd, arr3[1] = %hhd, arr3[2] = %hhd, arr3[3] = %hhd, "
         "arr3[4] = %hhd\n", arr3[0], arr3[1], arr3[2], arr3[3], arr3[4]);
  printf("arr4[0] = %ld, arr4[1] = %ld, arr4[2] = %ld, arr4[3] = %ld, arr4[4] "
         "= %ld\n", arr4[0], arr4[1], arr4[2], arr4[3], arr4[4]);
  return 0;
}
