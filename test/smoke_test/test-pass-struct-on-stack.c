// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: res->index0 = -12345678
// CHECK: res->index1 = 8
// CHECK: res->index2 = A
// CHECK: res->index3 = 12345678
// CHECK: res->index4 = -1234567891012345678
// CHECK: res->index5 = 1234567891012345678
// CHECK: *res->index6 = 2020
// CHECK: res->index0 = -12345678
// CHECK: res->index1 = 7
// CHECK: res->index2 = B
// CHECK: res->index3 = 12345676
// CHECK: res->index4 = -1234567891012345688
// CHECK: res->index5 = 1234567891012345698
// CHECK: *res->index6 = 2021
// CHECK: res->index0 = -22345678
// CHECK: res->index1 = 18
// CHECK: res->index2 = C
// CHECK: res->index3 = 12345679
// CHECK: res->index4 = -1234563891012345688
// CHECK: res->index5 = 1234567891012445698
// CHECK: *res->index6 = 2022

#include <stdio.h>

typedef struct list_info_s {
  int index0;
  short index1;
  char index2;
  unsigned index3;
  long index4;
  unsigned long index5;
  int *index6;
} list_info;

list_info __attribute__((noinline)) * iterate(void *pres) {
  list_info *res = (list_info *)pres;
  printf("res->index0 = %d\n", res->index0);
  printf("res->index1 = %hd\n", res->index1);
  printf("res->index2 = %c\n", res->index2);
  printf("res->index3 = %d\n", res->index3);
  printf("res->index4 = %ld\n", res->index4);
  printf("res->index5 = %ld\n", res->index5);
  printf("*res->index6 = %d\n", *res->index6);
  return res;
}

int main(int argc, char **argv) {
  list_info info;
  int v = 2020;
  info.index0 = -12345678;
  info.index1 = 8;
  info.index2 = 'A';
  info.index3 = 12345678;
  info.index4 = -1234567891012345678L;
  info.index5 = 1234567891012345678L;
  info.index6 = &v;
  iterate(&info);

  v = 2021;
  info.index1 = 7;
  info.index5 = 1234567891012345698L;
  info.index6 = &v;
  info.index3 = 12345676;
  info.index4 = -1234567891012345688L;
  info.index2 = 'B';
  info.index0 = -12345678;
  iterate(&info);

  v = 2022;
  info.index3 = 12345679;
  info.index1 = 18;
  info.index6 = &v;
  info.index5 = 1234567891012445698L;
  info.index2 = 'C';
  info.index0 = -22345678;
  info.index4 = -1234563891012345688L;
  iterate(&info);

  return 0;
}
