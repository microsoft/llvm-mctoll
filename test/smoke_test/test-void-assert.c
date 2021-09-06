// REQUIRES: system-linux
// RUN: clang -o %t %s -O3
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Ok
// CHECK-EMPTY

#include <stdio.h>
#include <stdlib.h>

// assert is not supported in llvm-mctoll yet.
// https://github.com/microsoft/llvm-mctoll/pull/124
// After this PR is merged, my_assert can be exchanged with assert
#define my_assert(cond)                                                        \
  if (!cond) {                                                                 \
    printf("Assertion " #cond " failed.\n");                                   \
    exit(1);                                                                   \
  }

typedef struct {
  int length;
  void *data;
} Data;

__attribute__((noinline)) void assert_func(Data *args) {
  my_assert(args->length);

  char *data = (char *)(args->data);
  my_assert(data);
}

int main(int argc, char *argv[]) {
  Data args;
  args.length = 4;
  args.data = "asdf";

  assert_func(&args);

  printf("Ok\n");

  return 0;
}
