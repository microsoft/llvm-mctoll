// REQUIRES: x86_64-linux
// RUN: clang -o %t %s -O3
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: TEST16MI :Pass
// CHECK-NEXT: TEST32MI :Pass
// CHECK-NEXT: TEST64MI :Pass
// CHECK-EMPTY

#include "stdint.h"
#include "stdio.h"

// Verify translation of testmi instruction
void __attribute__((noinline)) run_test16mi() {
  static short array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  static unsigned char result;
  
  __asm__ volatile("testw $5, 16+%1 \n\t"
		   "jnz non_zero%=\n\t"
		   "mov $0, %0\n\t"
		   "jmp done%=\n\t"
		   "non_zero%=:\n\t"
		   "mov $1, %0\n\t"
		   "done%=:\n\t"
		   :"=r"(result): "o"(array)
		   );
  printf("TEST16MI :%s\n", result?"Pass":"Fail");
}

void __attribute__((noinline)) run_test32mi() {
  static int array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  static unsigned char result;
  
  __asm__ volatile("testl $6, 24+%1 \n\t"
		   "jnz non_zero%=\n\t"
		   "mov $0, %0\n\t"
		   "jmp done%=\n\t"
		   "non_zero%=:\n\t"
		   "mov $1, %0\n\t"
		   "done%=:\n\t"
		   :"=r"(result): "o"(array)
		   );
  printf("TEST32MI :%s\n", result?"Pass":"Fail");
}


void __attribute__((noinline)) run_test64mi() {
  static long array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  static unsigned char result;
  
  __asm__ volatile("testq $7, 32+%1 \n\t"
		   "jnz non_zero%=\n\t"
		   "mov $0, %0\n\t"
		   "jmp done%=\n\t"
		   "non_zero%=:\n\t"
		   "mov $1, %0\n\t"
		   "done%=:\n\t"
		   :"=r"(result): "o"(array)
		   );
  printf("TEST64MI :%s\n", result?"Pass":"Fail");
}


int main() {
  run_test16mi();
  run_test32mi();
  run_test64mi();
  return 0;
}
