// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: ret : -1
#include <stdio.h>
#include <stdlib.h>

/* list data structures */
typedef struct list_data_s {
  int data;
} list_data;

int __attribute__((noinline)) func_test(int *p, int val) {
  int data = *p;
  return data - val;
}

int __attribute__((noinline)) call_me(list_data *a, list_data *b, int c) {
  int val1 = func_test(&(a->data), c);
  int val2 = func_test(&(b->data), c);
  return val1 - val2;
}

int main(int argc, char **argv) {
  list_data *list_a = (list_data *)malloc(sizeof(list_data));
  list_data *list_b = (list_data *)malloc(sizeof(list_data));

  list_a->data = 4;
  list_b->data = 5;

  int ret = call_me(list_a, list_b, 3);
  printf("ret : %d\n", ret);

  free(list_a);
  free(list_b);
  return 0;
}
