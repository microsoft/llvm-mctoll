// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK:State Input: 53
// CHECK:State Input: 48
// CHECK:State Input: 49
// CHECK:State Input: 50
// CHECK:State Input: 53
// CHECK:State Input: 48
// CHECK:State Input: 49
// CHECK:State Input: 50
// CHECK:State Input: 51
// CHECK:State Input: 53
// CHECK:State Input: 46
// CHECK:State Input: 53
// CHECK:State Input: 51
// CHECK:State Input: 53
// CHECK:State Input: 46
// CHECK:State Input: 53
// CHECK:State Input: 53
// CHECK:State Input: 46
// CHECK:State Input: 53
// CHECK:State Input: 48
// CHECK:State Input: 53
// CHECK:State Input: 46
// CHECK:State Input: 53
// CHECK:State Input: 48
// CHECK:State Input: 84
// CHECK:State Input: 48
// CHECK:State Input: 46
// CHECK:State Input: 51
// CHECK:ret 1

#include <stdio.h>

/* Default initialization patterns */
static unsigned char *intpat[4] = {
    (unsigned char *)"5012", (unsigned char *)"1234", (unsigned char *)"-874",
    (unsigned char *)"+122"};
static unsigned char *floatpat[4] = {
    (unsigned char *)"35.54400", (unsigned char *)".1234500",
    (unsigned char *)"-110.700", (unsigned char *)"+0.64400"};
static unsigned char *scipat[4] = {
    (unsigned char *)"5.500e+3", (unsigned char *)"-.123e-2",
    (unsigned char *)"-87e+832", (unsigned char *)"+0.6e-12"};
static unsigned char *errpat[4] = {
    (unsigned char *)"T0.3e-1F", (unsigned char *)"-T.T++Tq",
    (unsigned char *)"1T3.4e4z", (unsigned char *)"34.0e-T^"};

int call_func(signed short seed) {
  unsigned char *buf = 0;
  unsigned char *start;
  while (seed < 8) {
    switch (seed & 0x7) {
    case 0: /* int */
    case 1: /* int */
    case 2: /* int */
      buf = intpat[(seed >> 3) & 0x3];
      break;
    case 3: /* float */
    case 4: /* float */
      buf = floatpat[(seed >> 3) & 0x3];
      break;
    case 5: /* scientific */
    case 6: /* scientific */
      buf = scipat[(seed >> 3) & 0x3];
      break;
    case 7: /* invalid */
      buf = errpat[(seed >> 3) & 0x3];
      break;
    default: /* Never happen, just to make some compilers happy */
      break;
    }
    start = buf;
    printf("State Input: %hhu\n", start[0]);
    printf("State Input: %hhu\n", start[1]);
    printf("State Input: %hhu\n", start[2]);
    printf("State Input: %hhu\n", start[3]);
    seed++;
  }
  return 1;
}

int main() {
  int ret = call_func(1);
  printf("ret %d\n", ret);
  return 0;
}
