// REQUIRES: system-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 42.0 42.0 42.0 42.0 42 42 42 42
// CHECK-EMPTY

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int main() {
  int32_t a = 42;
  int64_t b = 42;
  float c = 42.5;
  double d = 42.5;

  printf("%.1f %.1f %.1f %.1f %d %" PRId64 " %d %" PRId64 "\n",
      (float) a, (double) a,
      (float) b, (double) b,
      (int32_t) c, (int64_t) c,
      (int32_t) d, (int64_t) d);

  return 0;
}
