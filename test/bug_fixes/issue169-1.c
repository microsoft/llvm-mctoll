// REQUIRES: system-linux
// RUN: clang -O3 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999
// CHECK-EMPTY

#include <stdio.h>

void foo() {
    for(int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            printf("%d", i);
        }
    }
    printf("\n");
}
int main() {
    foo();
    return 0;
}
