// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Hello from main!
// CHECK-NEXT: Bye!
// CHECK-EMPTY

#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
void exit_with_msg(const char *msg) {
  printf("%s\n", msg);
  exit(0);
}

int main() {
  printf("Hello from main!\n");
  exit_with_msg("Bye!");
  return 0;
}
