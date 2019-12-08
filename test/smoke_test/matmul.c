// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s -check-prefix=DEFAULT-OPT
// DEFAULT-OPT: TEST PASSED
#include <stdio.h>

#define ROWS 10

int matmul(int First[][ROWS], int Second[][ROWS], int Result[][ROWS]) {
  for (int i = 0; i < ROWS; i++) {
    for (int j = 0; j < ROWS; j++) {
      for (int k = 0; k < ROWS; k++) {
        Result[i][k] += First[i][k] * Second[k][j];
      }
    }
  }
  return 0;
}

int main() {
  int MatOne[ROWS][ROWS] = {{619, 720, 127, 481, 931, 816, 813, 233, 566, 247},
                            {985, 724, 205, 454, 863, 491, 741, 242, 949, 214},
                            {733, 859, 335, 708, 621, 574, 73, 654, 730, 472},
                            {419, 436, 278, 496, 867, 210, 399, 680, 480, 51},
                            {878, 465, 811, 169, 869, 675, 611, 697, 867, 561},
                            {862, 687, 507, 283, 482, 129, 807, 591, 733, 623},
                            {150, 238, 59, 379, 684, 877, 625, 169, 643, 105},
                            {170, 607, 520, 932, 727, 476, 693, 425, 174, 647},
                            {73, 122, 335, 530, 442, 853, 695, 249, 445, 515},
                            {909, 545, 703, 919, 874, 474, 882, 500, 594, 612}},
      MatTwo[ROWS][ROWS], MatThree[ROWS][ROWS];

  // Initialize MatTwo as identity matrix
  for (int i = 0; i < ROWS; i++) {
    for (int j = 0; j < ROWS; j++) {
      if (i == j) {
        MatTwo[i][j] = 1;
      } else {
        MatTwo[i][j] = 0;
      }
    }
  }
  // Initialize result matrix
  for (int i = 0; i < ROWS; i++) {
    for (int j = 0; j < ROWS; j++) {
      MatThree[i][j] = 0;
    }
  }

  matmul(MatOne, MatTwo, MatThree);

  for (int i = 0; i < ROWS; i++) {
    for (int j = 0; j < ROWS; j++) {
      if (MatOne[i][j] != MatThree[i][j]) {
        printf("TEST FAILED\n");
      }
    }
  }
  printf("TEST PASSED\n");
}
