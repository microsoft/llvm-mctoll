// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: ret : -1
// CHECK: a : 0x7ffcd1e b : 0x7fffab0f c : 0x7fffef2d N : 1024
// CHECK-EMPTY:
#include <stdint.h>
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

// This function's binary uses argument register that is alos a tired-def.  To
// discover first use of a function argument, function prototype discovery
// algorithm handles these situations by should first look at uses and then defs
// of an instruction.
void __attribute__((noinline))
use_tied_arg(int n, unsigned c, unsigned a, unsigned b) {
  printf("a : 0x%x b : 0x%x c : 0x%x N : %d\n", (a ^ 0xff), (b ^ 0xff),
         (c ^ 0xff), n);
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

  use_tied_arg(1024, 0x7fffefd2, 0x7ffcde1, 0x7fffabf0);
  return 0;
}
