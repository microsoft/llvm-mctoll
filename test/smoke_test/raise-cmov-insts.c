// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: CMOVE :10
// CHECK: CMOVG :4
// CHECK: CMOVL :10
// CHECK: CMOVA :4

#include <stdio.h>
int __attribute__((noinline)) test_cmove(int a) {
  int ret = -1;
  if (a == 10)
    ret = 4;
  else
    ret = 10;
  return ret;
}

int __attribute__((noinline)) test_cmovg(int a) {
  int ret = -1;
  if (a > 10)
    ret = 4;
  else
    ret = 10;
  return ret;
}

int __attribute__((noinline)) test_cmovl(int a) {
  int ret = -1;
  if (a < 10)
    ret = 4;
  else
    ret = 10;
  return ret;
}

int __attribute__((noinline)) test_cmova(unsigned a) {
  int ret = -1;
  if (a > 10)
    ret = 4;
  else
    ret = 10;
  return ret;
}

int main(int argc, char **argv) {
  int ret = 0;

  ret = test_cmove(15);
  printf("CMOVE :%d\n", ret);
  ret = test_cmovg(15);
  printf("CMOVG :%d\n", ret);
  ret = test_cmovl(15);
  printf("CMOVL :%d\n", ret);
  ret = test_cmova(15);
  printf("CMOVA :%d\n", ret);

  return 0;
}
