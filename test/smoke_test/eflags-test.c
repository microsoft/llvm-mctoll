// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: State buf: +122
// CHECK: State Input: 5012,5012,5012

#include <stdio.h>
#include <stdlib.h>

/* Default initialization patterns */
static unsigned char *intpat[4] = {
    (unsigned char *)"5012", (unsigned char *)"1234", (unsigned char *)"-874",
    (unsigned char *)"+122"};

void __attribute__((noinline))
core_init_state(unsigned int size, signed short seed, unsigned char *p) {
  unsigned int total = 0, next = 0, i;
  unsigned char *buf = 0;
  unsigned char *start = p;
  size--;
  next = 0;
  while ((total + next + 1) < size) {
    if (next > 0) {
      for (i = 0; i < next; i++)
        *(p + total + i) = buf[i];
      *(p + total + i) = ',';
      total += next + 1;
    }
    seed++;
    next = 8;
    if ((seed & 0x7) < 3) {
      buf = intpat[(seed >> 3) & 0x3];
      next = 4;
    }
  }

  size++;
  while (total < size) {
    *(p + total) = 0;
    total++;
  }
  printf("State buf: %s\n", buf);
  printf("State Input: %s\n", start);
}

int main(int argc, char **argv) {
  unsigned int sz = 666;
  unsigned char *p = (unsigned char *)malloc(sizeof(unsigned char)*sz+1);
  core_init_state(sz, 0, p);
  return 0;
}
