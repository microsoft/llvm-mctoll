// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck --check-prefix=RESULT %s
// RESULT:buf = 2d
// RESULT:buf = 2e
// RESULT:buf = 31
// RESULT:buf = 32

#include <stdio.h>
#include <stdlib.h>

static unsigned char *Apat[4] = {
    (unsigned char *)"5012", (unsigned char *)"1234", (unsigned char *)"-874",
    (unsigned char *)"+122"};
static unsigned char *Bpat[4] = {
    (unsigned char *)"35.54400", (unsigned char *)".1234500",
    (unsigned char *)"-110.700", (unsigned char *)"+0.64400"};
static unsigned char *Cpat[4] = {
    (unsigned char *)"5.500e+3", (unsigned char *)"-.123e-2",
    (unsigned char *)"-87e+832", (unsigned char *)"+0.6e-12"};
static unsigned char *Dpat[4] = {
    (unsigned char *)"T0.3e-1F", (unsigned char *)"-T.T++Tq",
    (unsigned char *)"1T3.4e4z", (unsigned char *)"34.0e-T^"};

int __attribute__((noinline)) foo(unsigned int size, signed short seed) {
  unsigned int next = 0, total = 0;
  unsigned char *buf = malloc(4 * sizeof(unsigned char));
  while ((total + next + 1) < size) {
    if (next > 0) {
      total += next + 1;
    }
    seed++;
    switch (seed & 0x7) {
    case 0: /* int */
    case 1: /* int */
    case 2: /* int */
      buf = Apat[(seed >> 3) & 0x3];
      next = next + 4;
      break;
    case 3: /* float */
    case 4: /* float */
      buf = Bpat[(seed >> 3) & 0x3];
      next = next + 8;
      break;
    case 5: /* scientific */
    case 6: /* scientific */
      buf = Cpat[(seed >> 3) & 0x3];
      next = next + 8;
      break;
    case 7: /* invalid */
      buf = Dpat[(seed >> 3) & 0x3];
      next = next + 8;
      break;
    default: /* Never happen, just to make some compilers happy */
      break;
    }
  }

  printf("buf = %x\n", buf[0]);
  printf("buf = %x\n", buf[1]);
  printf("buf = %x\n", buf[2]);
  printf("buf = %x\n", buf[3]);
  return 1;
}

int main(int argc, char **argv) {
  foo(66, 8);
  printf("Test\n");
  return 0;
}
