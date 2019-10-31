// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s
// CHECK: ret 90
// CHECK: ret 250

/*
 * Code will poduce MI as follows:
 * CALL64pcrel32 48, <0x55c021faa7a8>, implicit $rsp, implicit $ssp
 * $ebx = MOVSX32rr16 $ax, <0x55c021faa8c8>
 */

#include <stdio.h>
#define call_big(x) (0xf000 | (x))

signed short A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
signed short B[16] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 12, 2, 2, 2};
static signed int C[16] = {0};

signed short __attribute__((noinline))
call_test(unsigned int N, signed int *C, signed short *A, signed short *B,
          signed short val);
signed short call_sum(unsigned int N, signed int *C, signed short clipval);

void call_mul_const(unsigned int N, signed int *C, signed short *A,
                    signed short val);
void call_mul_vect(unsigned int N, signed int *C, signed short *A,
                   signed short *B);
void call_add_const(unsigned int N, signed short *A, signed short val);

unsigned short bar(unsigned char data, unsigned short arg) {
  unsigned char i = 0, x16 = 0, carry = 0;

  for (i = 0; i < 8; i++) {
    x16 = (unsigned char)((data & 1) ^ ((unsigned char)arg & 1));
    data >>= 1;

    if (x16 == 1) {
      arg ^= 0x4002;
      carry = 1;
    } else
      carry = 0;
    arg >>= 1;
    if (carry)
      arg |= 0x8000;
    else
      arg &= 0x7fff;
  }
  return arg;
}
unsigned short foo(unsigned short newval, unsigned short arg) {
  arg = bar((unsigned char)(newval), arg);
  arg = bar((unsigned char)((newval) >> 8), arg);
  return arg;
}

unsigned short call(signed short newval, unsigned short arg) {
  return foo((unsigned short)newval, arg);
}

int bench_call() {
  unsigned int N = 4;
  short val = 2;
  unsigned int arg = 0x0102;
  signed short ret1 = call_test(N, C, A, B, val);
  printf("ret %d\n", ret1);
  int result2 = call(ret1, arg);
  return result2;
}

signed short __attribute__((noinline))
call_test(unsigned int N, signed int *C, signed short *A, signed short *B,
          signed short val) {
  unsigned short arg = 0;
  signed short clipval = call_big(val);

  call_mul_const(N, C, A, val);
  arg = call(call_sum(N, C, clipval), arg);

  call_mul_vect(N, C, A, B);
  arg = call(call_sum(N, C, clipval), arg);

  call_add_const(N, A, -val);
  return arg;
}

signed short call_sum(unsigned int N, signed int *C, signed short clipval) {
  signed int tmp = 0, prev = 0, cur = 0;
  signed short ret = 0;
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      cur = C[i * N + j];
      tmp += cur;
      if (tmp > clipval) {
        ret += 10;
        tmp = 0;
      } else {
        ret += (cur > prev) ? 1 : 0;
      }
      prev = cur;
    }
  }
  return ret;
}

void call_mul_const(unsigned int N, signed int *C, signed short *A,
                    signed short val) {
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      C[i * N + j] = (signed int)A[i * N + j] * (signed int)val;
    }
  }
}

void call_mul_vect(unsigned int N, signed int *C, signed short *A,
                   signed short *B) {
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    C[i] = 0;
    for (j = 0; j < N; j++) {
      C[i] += (signed int)A[i * N + j] * (signed int)B[j];
    }
  }
}

void call_add_const(unsigned int N, signed short *A, signed short val) {
  unsigned int i, j;
  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      A[i * N + j] += val;
    }
  }
}

int main() {
  int ret = bench_call();
  printf("ret %d\n", ret);
  return 0;
}
