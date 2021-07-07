// REQUIRES: system-linux
// RUN: clang -O3 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h %t
// RUN: clang -O3 -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Val : 99
// CHECK-NEXT: Val : 98
// CHECK-NEXT: Val : 97
// CHECK-NEXT: Val : 96
// CHECK-NEXT: Val : 95
// CHECK-NEXT: Val : 94
// CHECK-NEXT: Val : 93
// CHECK-NEXT: Val : 92
// CHECK-NEXT: Val : 91
// CHECK-EMPTY
#include <stdio.h>
#include <stdlib.h>

struct Foo {
  int val;
  struct Foo *next;
};

void __attribute__ ((noinline)) visit(struct Foo *f) {
  while (f->next != 0) {
    f = f->next;
    printf("Val : %d\n", f->val);
  }
  return;
}

void __attribute__ ((noinline)) init(struct Foo **f) {
  int v = 100;
  while (v > 90) {
    if (*f == NULL) {
      *f = (struct Foo*) malloc(sizeof(struct Foo));
    }
    (*f)->val = v--;
    (*f)->next = NULL;
    f = &((*f)->next);
  }
  return;
}

int main() {
  struct Foo* l = NULL;
  init(&l);
  visit(l);
  return 0;
}
