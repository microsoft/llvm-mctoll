// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: ret is: 0

#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long ee_ptr_int;

#define align_mem(x) (void *)(4 + (((ee_ptr_int)(x)-1) & ~3))
#define matrix_clip(x, y) ((y) ? (x)&0x0ff : (x)&0x0ffff)

typedef struct MAT_PARAMS_S {
  int N;
  short *A;
  short *B;
  int *C;
} mat_params;

unsigned int __attribute__((noinline))
call_func(unsigned int blksize, void *memblk, int seed, mat_params *p) {
  unsigned int N = 0;
  short *A;
  short *B;
  int order = 1;
  short val;
  unsigned int i = 0, j = 0;
  if (seed == 0)
    seed = 1;
  while (j < blksize) {
    i++;
    j = i * i * 2 * 4;
  }
  N = i - 1;
  A = (short *)align_mem(memblk);
  B = A + N * N;

  for (i = 0; i < N; i++) {
    for (j = 0; j < N; j++) {
      seed = ((order * seed) % 65536);
      val = (seed + order);
      val = matrix_clip(val, 0);
      B[i * N + j] = val;
      val = (val + order);
      val = matrix_clip(val, 1);
      A[i * N + j] = val;
      order++;
    }
  }
  p->A = A;
  p->B = B;
  p->C = (int *)align_mem(B + N * N);
  p->N = N;
  return N;
}

int main(int argc, char **argv) {
  void *mem = malloc(6);
  mat_params *p = (mat_params *)malloc(sizeof(mat_params));

  unsigned int ret = call_func(5, mem, 2, p);
  printf("ret is: %d\n", ret);

  free(mem);
  free(p);
  return 0;
}
