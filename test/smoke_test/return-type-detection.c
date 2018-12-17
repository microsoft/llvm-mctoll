// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
/* Test generated .ll file */
// RUN: cat %t-dis.ll | FileCheck %S/Inputs/return-type-detection-ll
/* Test execution of raised binary */
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %S/Inputs/return-type-detection-dis-run

/* This tests correct detection of void return type of a function that
   calls another function in its return basic block. */
#include <stdio.h>

/* This is the function with void return. It also calls a function in
   its return basic block. */
void void_return_function() {
  unsigned int val = 5;
  printf("Val = %d\n", val);
}

int int_return_function() { return 42; }

int main(int argc, char **argv) {
  void_return_function();
  printf("Val = %d\n", int_return_function());
  return 0;
}
