// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: errpat!!!

#include <stdlib.h>
#include <stdio.h>

static unsigned char *intpat  =(unsigned char *)"122";
static unsigned char *floatpat=(unsigned char *)"0.64400";
static unsigned char *scipat  =(unsigned char *)"0.6e";
static unsigned char *errpat  =(unsigned char *)"34.0";

void __attribute__((noinline)) test_global_value(short seed) {
  unsigned char *buf=0;
  switch (seed) {
  case 2: 
    buf=intpat;
    printf("intpat!!!\n");
  break;
  case 4: 
    buf=scipat;
    printf("scipat!!!\n");
  break;
  case 7: 
    buf=floatpat;
    printf("floatpat!!!\n");
  break;
  case 14:
    buf=errpat;
    printf("errpat!!!\n");
  break;
  default:
  break;
  }
}

int main() {
  short d = 14;
  test_global_value(d);
  return 0; 
}
