// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: llvm-strings %t-opt-dis.ll 2>&1 | FileCheck --check-prefix=GLTEXT %s
// GLTEXT:switch i32 %arg2, label %bb.3 [
// GLTEXT:  i32 0, label %bb.3
// GLTEXT:  i32 1, label %bb.3
// GLTEXT:  i32 2, label %bb.3
// GLTEXT:  i32 3, label %bb.5
// GLTEXT:  i32 4, label %bb.5
// GLTEXT:  i32 5, label %bb.2
// GLTEXT:  i32 6, label %bb.2
// GLTEXT:  i32 7, label %bb.6
// GLTEXT:]
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck --check-prefix=RESULT %s
// RESULT:buf = 35
// RESULT:buf = 30
// RESULT:buf = 31
// RESULT:buf = 32
// RESULT:buf = 35
// RESULT:buf = 30
// RESULT:buf = 31
// RESULT:buf = 32
// RESULT:buf = 35
// RESULT:buf = 30
// RESULT:buf = 31
// RESULT:buf = 32
// RESULT:buf = 33
// RESULT:buf = 35
// RESULT:buf = 2e
// RESULT:buf = 35
// RESULT:buf = 33
// RESULT:buf = 35
// RESULT:buf = 2e
// RESULT:buf = 35
// RESULT:buf = 35
// RESULT:buf = 2e
// RESULT:buf = 35
// RESULT:buf = 30
// RESULT:buf = 35
// RESULT:buf = 2e
// RESULT:buf = 35
// RESULT:buf = 30
// RESULT:buf = 54
// RESULT:buf = 30
// RESULT:buf = 2e
// RESULT:buf = 33
// RESULT:buf = 31
// RESULT:buf = 32
// RESULT:buf = 33
// RESULT:buf = 34
// RESULT:Test

/*
 * Code will poduce MI as follows:
 * bb.2:
 *  successors: %bb.3
 * NOOPW $rax, 1, $rax, 0, $cs, <0x55e123f0e4e8>
 * NOOPL $rax, 1, $noreg, 0, $noreg, <0x55e123f0e5e8>
 * $eax = MOV32ri 8, <0x55e123f0e708>
 * $rsi = MOV64rr $r9, <0x55e123f0f838>
 */
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

int __attribute__((noinline)) call_func(unsigned int size, signed short seed) {
  unsigned int next = 0;
  unsigned char *buf = malloc(4 * sizeof(unsigned char));

  while ((next + 1) < size) {
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
  call_func(66, 0);
  call_func(66, 1);
  call_func(66, 2);
  call_func(66, 3);
  call_func(66, 4);
  call_func(66, 5);
  call_func(66, 6);
  call_func(66, 7);
  call_func(66, 8);
  printf("Test\n");
  return 0;
}
