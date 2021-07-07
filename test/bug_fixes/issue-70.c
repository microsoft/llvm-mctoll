// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/string.h -I /usr/include/time.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: -9.556800
// CHECK-NEXT: 4.002900
// CHECK-NEXT: 7.287300
// CHECK-NEXT: -6.269600
// CHECK-NEXT: 7.287300
// CHECK-NEXT: -4.724000
// CHECK-NEXT: -4.724000
// CHECK-NEXT: 4.002900
// CHECK-NEXT: 10.378500
// CHECK-NEXT: -6.269600
// CHECK-EMPTY
#include <stdio.h>
#include <time.h>

#define row 256
#define col 100

int main()
{
    double input[col] = {0};
    double weight[row][col] = {0};

    for(int i = 0; i < col; i++)
    {
        if(i % 4 == 0 || i % 6 ==0)
            input[i] = 1;
    }

    //printf("%d\n", input[8]);


    for (int i = 0; i< row; i++){
        for (int j = 0; j < col; j++){
            weight[i][j] = 0.1213;
        }
    }

    for (int i = 0; i< row; i++){
        for (int j = 0; j < col; j++){
            if((i % 2 == 0 || i % 5 == 0) && (j % 3 == 0 || i % 8 == 0))
            {
                weight[i][j] = 0.3145;
            }
        }
    }
    for (int i = 0; i< row; i++){
        for (int j = 0; j < col; j++){
            if((i % 3 == 0 || i % 5 == 0) && (j % 4 == 0 || i % 7 == 0))
            {
                weight[i][j] = -0.2896;
            }
        }
    }

    double output[row] = {0};
    for(int i = 0; i < 256; i++)
        for(int j = 0; j < col; j++) {
            output[i] += weight[i][j] * input[j];
        }

    for(int j = 0; j < 10; j++)
    {
        printf("%f\n", output[j]);
    }
    return 0;

}
