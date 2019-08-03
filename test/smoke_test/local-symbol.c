// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: time_val: 1

#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv) {
  static clock_t start_time_val;
  static clock_t stop_time_val;

  clock_gettime(CLOCK_REALTIME, &start_time_val);
  sleep(1);
  clock_gettime(CLOCK_REALTIME, &stop_time_val);
  
  printf("time_val: %ld\n", stop_time_val - start_time_val);
  return 0;
}
