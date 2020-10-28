// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/time.h -I /usr/include/unistd.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck --check-prefix=RESULT %s
// RESULT:time_val:

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define GETMYTIME(_t) (*_t = clock())
#define MYTIMEDIFF(fin, ini) ((fin) - (ini))
#define EE_TICKS_PER_SEC (CLOCKS_PER_SEC / 1)
static clock_t start_time_val, stop_time_val;

unsigned int __attribute__((noinline)) time_in_secs(unsigned int ticks) {
  unsigned int retval = ((unsigned int)ticks) / (unsigned int)EE_TICKS_PER_SEC;
  return retval;
}

void start_time(void) { GETMYTIME(&start_time_val); }

void stop_time(void) { GETMYTIME(&stop_time_val); }

int main(int argc, char **argv) {
  start_time();
  sleep(1);
  stop_time();
  printf("time_val: %ld\n", stop_time_val - start_time_val);
  return 0;
}
