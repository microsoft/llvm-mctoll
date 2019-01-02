// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Value 5
// CHECK: Value 8

/*
 * This test will produce the mi as follows:
 *   TEST8rr $dil, $dil
 *   CMP8ri $bl, 3
 */

#include <stdio.h>
void func(unsigned char i, int j) {
  unsigned char a;
  if (j == 2)
    a = 4;

  if (i == 0)
    a = 8;

  a = a + i;

  if (a == 3)
    printf("Value %hhu\n", a);

  printf("Value %hhu\n", a);
  return;
}

int main(int argc, char **argv) {
  func(1, 2);
  func(0, 3);
  return 0;
}
