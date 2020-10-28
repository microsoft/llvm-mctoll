// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: ret1 - ret2 : 1
#include <stdio.h>
#include <stdlib.h>

/* list data structures */
typedef struct list_data_s {
  int index;
} list_data;

typedef struct list_info_s {
  int index;
} list_info;

int __attribute__ ((noinline)) call_info(list_info *info, int c) {
  return info->index - c;
}

int __attribute__ ((noinline)) call_data(list_data *data, int c) {
  return data->index - c;
}

int main(int argc, char **argv) {
  list_data *data = (list_data *)malloc(sizeof(list_data));
  list_info *info = (list_info *)malloc(sizeof(list_info));

  data->index = 6;
  info->index = 5;

  int ret1 = call_data(data, 3);
  int ret2 = call_info(info, 3);
  printf("ret1 - ret2 : %d\n", ret1 - ret2);

  free(data);
  free(info);
  return 0;
}
