// REQUIRES: system-linux
// RUN: clang -o %t %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK:res->index0 = 0
// CHECK:res->index1 = 1
// CHECK:res->index2 = 2
// CHECK:res->index3 = 3
// CHECK:res->index4 = 4
// CHECK:res->index5 = 5
// CHECK:res->index6 = 6

#include <stdio.h>

typedef struct list_info_s {
  short index0;
  short index1;
  short index2;
  short index3;
  short index4;
  short index5;
  short index6;
} list_info;

list_info __attribute__((noinline)) * iterate(void *pres) {
  list_info *res = (list_info *)pres;
  printf("res->index0 = %d\n", res->index0);
  printf("res->index1 = %d\n", res->index1);
  printf("res->index2 = %d\n", res->index2);
  printf("res->index3 = %d\n", res->index3);
  printf("res->index4 = %d\n", res->index4);
  printf("res->index5 = %d\n", res->index5);
  printf("res->index6 = %d\n", res->index6);
  return res;
}

int main(int argc, char **argv) {
  list_info info;
  info.index1 = 1;
  info.index5 = 5;
  info.index6 = 6;
  info.index3 = 3;
  info.index4 = 4;
  info.index2 = 2;
  info.index0 = 0;
  iterate(&info);
  return 0;
}
