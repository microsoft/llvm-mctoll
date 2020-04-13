// REQUIRES: system-linux
// RUN: clang -o %t %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK:data[7080]
// CHECK:idx [7fff]
// CHECK:idx2 [6666]

#include <stdio.h>

typedef struct list_data_s {
  signed short data16;
  signed short idx;
  signed short idx2;
} list_data;

int __attribute__((noinline)) foo(list_data *info) {
  printf("data[%04x]\n", info->data16);
  printf("idx [%04x]\n", info->idx);
  printf("idx2 [%04x]\n", info->idx2);
  return 0;
}

int __attribute__((noinline)) call_func() {
  list_data infoT;
  infoT.idx2 = 0x6666;
  infoT.idx = 0x7fff;
  infoT.data16 = 0x7080;
  foo(&infoT);
  return 0;
}

int main() {
  call_func();
  return 0;
}
