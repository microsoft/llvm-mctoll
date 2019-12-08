// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:34.0

/*
 * This code tests raising of static global pointer.
 */

#include <stdio.h>
#include <stdlib.h>

static unsigned char *errpat = (unsigned char *)"34.0";

void test_global_value() {
  unsigned char *buf = 0;
  buf = errpat;
  printf("%s\n", buf);
}

int main() {
  test_global_value();
  return 0;
}
