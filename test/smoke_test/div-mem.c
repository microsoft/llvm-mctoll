// REQUIRES: system-linux
// RUN: clang -O1 -fno-inline -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK-EMPTY
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK: 0  1  2  3  4  5  6  7  8  9
// CHECK-EMPTY

#include <stdio.h>
#include <inttypes.h>

typedef struct {
  int32_t len;
  int64_t len64;
} Params;

void loop(Params *params) {
  for (int32_t i = 0; i < params->len * params->len; ++i) {
    if (i > 0 && i % params->len == 0)
      printf("\n");
    printf("%d  ", i % params->len);
  }
  printf("\n\n");
  for (int64_t i = 0; i < params->len64 * params->len64; ++i) {
    if (i > 0 && i % params->len64 == 0)
      printf("\n");
    printf("%" PRId64 "  ", i % params->len64);
  }
  printf("\n");
}

int main(void) {
  Params params;
  params.len = 10;
  params.len64 = 10;

  loop(&params);

  return 0;
}
