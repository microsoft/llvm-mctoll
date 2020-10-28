// REQUIRES: x86_64-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdlib.h -I /usr/include/stdio.h  %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Test passed

#include <stdio.h>
#include <stdlib.h>

typedef struct list_head_s {
  struct list_head_s *next;
} list_head;

__attribute__((noinline)) list_head *core_list_reverse(list_head *list) {
  list_head *next = NULL, *tmp;
  while (list) {
    tmp = list->next;
    list->next = next;
    next = list;
    list = tmp;
  }
  return next;
}

int main(int argc, char **argv) {
  list_head *a = (list_head *)malloc(sizeof(list_head));
  if (a == NULL) {
    printf("First malloc failed\n");
    return -1;
  }
  list_head *b = (list_head *)malloc(sizeof(list_head));
  if (b == NULL) {
    printf("Second malloc failed\n");
    return -1;
  }
  a->next = b;
  list_head *c = (list_head *)malloc(sizeof(list_head));
  if (c == NULL) {
    printf("Third malloc failed\n");
    return -1;
  }
  b->next = c;
  c->next = NULL;

  list_head *d = core_list_reverse(a);
  if ((d == c) && (d->next == b) && (d->next->next == a) &&
      (d->next->next->next == NULL))
    printf("Test passed\n");
  else
    printf("Test failed\n");

  return 0;
}
