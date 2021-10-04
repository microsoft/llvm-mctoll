// REQUIRES: system-linux
// RUN: clang -o %t %s -O3 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/string.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: red[0] = 0
// CHECK-NEXT: green[0] = 0
// CHECK-NEXT: blue[0] = 0
// CHECK-NEXT: red[1] = 0
// CHECK-NEXT: green[1] = 0
// CHECK-NEXT: blue[1] = 1
// CHECK-NEXT: red[2] = 0
// CHECK-NEXT: green[2] = 1
// CHECK-NEXT: blue[2] = 0
// CHECK-NEXT: red[3] = 1
// CHECK-NEXT: green[3] = 0
// CHECK-NEXT: blue[3] = 0
// CHECK-NEXT: red[4] = 0
// CHECK-NEXT: green[4] = 0
// CHECK-NEXT: blue[4] = 1
// CHECK-NEXT: red[5] = 0
// CHECK-NEXT: green[5] = 1
// CHECK-NEXT: blue[5] = 0
// CHECK-NEXT: red[6] = 1
// CHECK-NEXT: green[6] = 0
// CHECK-NEXT: blue[6] = 0
// CHECK-NEXT: red[7] = 0
// CHECK-NEXT: green[7] = 0
// CHECK-NEXT: blue[7] = 1
// CHECK-NEXT: red[8] = 0
// CHECK-NEXT: green[8] = 1
// CHECK-NEXT: blue[8] = 0
// CHECK-NEXT: red[9] = 1
// CHECK-NEXT: green[9] = 0
// CHECK-NEXT: blue[9] = 0
// CHECK-NEXT: red[10] = 0
// CHECK-NEXT: green[10] = 0
// CHECK-NEXT: blue[10] = 1
// CHECK-NEXT: red[11] = 0
// CHECK-NEXT: green[11] = 1
// CHECK-NEXT: blue[11] = 0
// CHECK-NEXT: red[12] = 1
// CHECK-NEXT: green[12] = 0
// CHECK-NEXT: blue[12] = 0
// CHECK-NEXT: red[13] = 0
// CHECK-NEXT: green[13] = 0
// CHECK-NEXT: blue[13] = 1
// CHECK-NEXT: red[14] = 0
// CHECK-NEXT: green[14] = 1
// CHECK-NEXT: blue[14] = 0
// CHECK-NEXT: red[15] = 1
// CHECK-NEXT: green[15] = 0
// CHECK-NEXT: blue[15] = 0
// CHECK-NEXT: red[16] = 0
// CHECK-NEXT: green[16] = 0
// CHECK-NEXT: blue[16] = 1
// CHECK-NEXT: red[17] = 0
// CHECK-NEXT: green[17] = 1
// CHECK-NEXT: blue[17] = 0
// CHECK-EMPTY

#include <stdio.h>
#include <string.h>

typedef struct {
  int size;
  char *data;
} Params;

__attribute__((noinline)) void test(Params params) {
  int red[256];
  int green[256];
  int blue[256];

  memset(&(red[0]), 0, sizeof(int) * 256);
  memset(&(green[0]), 0, sizeof(int) * 256);
  memset(&(blue[0]), 0, sizeof(int) * 256);

  for (int i = 0; i < params.size; i += 3) {
    unsigned char *val = (unsigned char *)&(params.data[i]);
    blue[*val]++;

    val = (unsigned char *)&(params.data[i + 1]);
    green[*val]++;

    val = (unsigned char *)&(params.data[i + 2]);
    red[*val]++;
  }

  for (int i = 0; i < 18; i++) {
    printf("red[%d] = %d\n", i, red[i]);
    printf("green[%d] = %d\n", i, green[i]);
    printf("blue[%d] = %d\n", i, blue[i]);
  }
}

int main(void) {
  Params params;
  params.size = 18;
  char data[18] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
  params.data = data;

  test(params);

  return 0;
}
