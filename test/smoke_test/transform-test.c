// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/transform.c -shared -fPIC -Os
// RUN: llvm-mctoll -d %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Result: 0x102010301020104

#include <stdint.h>
#include <stdio.h>

extern void increment8(uint8_t* arr, int n);
extern void increment16(uint16_t* arr, int n);
extern void increment32(uint32_t* arr, int n);
extern void increment64(uint64_t* arr, int n);


int main() {
  uint64_t arr[] = {0};
  increment8((uint8_t *)arr, 8);   // 1 1 1 1 1 1 1 1
  increment16((uint16_t *)arr, 4); // 2 1 2 1 2 1 2 1
  increment32((uint32_t *)arr, 2); // 3 1 2 1 3 1 2 1
  increment64(arr, 1);             // 4 1 2 1 3 1 2 1
  printf("Result: 0x%lx\n", arr[0]);
  return 0;
}
