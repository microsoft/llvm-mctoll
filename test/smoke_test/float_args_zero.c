// REQUIRES: system-linux
// RUN: clang -O3 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: cat %t-dis.ll 2>&1 | FileCheck %s
// CHECK: %{{.*}} = call i32 (i8*, ...) @printf(i8* {{.*}}), double %{{.*}})

#include <stdio.h>

int main() {
  printf("%.1f\n", 0.0);
  return 0;
}
