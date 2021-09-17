// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: bt 3 1: CF = 1
// CHECK: bt 3 2: CF = 0
// CHECK: bt 3 1: CF = 1
// CHECK: bt 3 2: CF = 0
// CHECK: bt 3 1: CF = 1
// CHECK: bt 3 2: CF = 0
// CHECK: bt 3 1: CF = 1
// CHECK: bt 3 2: CF = 0
// CHECK: bt 3 2: CF = 0, value after = 7
// CHECK: bt 3 1: CF = 1, value after = 1
// CHECK: bt 3 0: CF = 1, value after = 2
// CHECK: bt 3 0: CF = 1, value after = 2
// CHECK: bt 3 1: CF = 1, value after = 3
// CHECK: bt 3 2: CF = 0, value after = 3
// CHECK: bt 3 8: CF = 0, value after = 259
// CHECK: bt 2 33: CF = 1
// CHECK: bt 2 1: CF = 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-bt.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 4

    mov eax, 3
    bt eax, 1
    mov esi, 3
    mov edx, 1
    jc .carry_1

    mov ecx, 0
    jmp .print_1

.carry_1:
    mov ecx, 1

.print_1:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov eax, 3
    bt eax, 2
    mov esi, 3
    mov edx, 2
    jc .carry_2

    mov ecx, 0
    jmp .print_2

.carry_2:
    mov ecx, 1

.print_2:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov eax, 3
    mov edx, 1
    bt eax, edx
    mov esi, 3
    jc .carry_3

    mov ecx, 0
    jmp .print_3

.carry_3:
    mov ecx, 1

.print_3:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov eax, 3
    mov edx, 2
    bt eax, edx
    mov esi, 3
    jc .carry_4

    mov ecx, 0
    jmp .print_4

.carry_4:
    mov ecx, 1

.print_4:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    bt dword ptr [.L.val], 1
    mov esi, 3
    mov edx, 1
    jc .carry_5

    mov ecx, 0
    jmp .print_5

.carry_5:
    mov ecx, 1

.print_5:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    bt dword ptr [.L.val], 2
    mov esi, 3
    mov edx, 2
    jc .carry_6

    mov ecx, 0
    jmp .print_6

.carry_6:
    mov ecx, 1

.print_6:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov edx, 1
    bt dword ptr [.L.val], edx
    mov esi, 3
    jc .carry_7

    mov ecx, 0
    jmp .print_7

.carry_7:
    mov ecx, 1

.print_7:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov edx, 2
    bt dword ptr [.L.val], edx
    mov esi, 3
    jc .carry_8

    mov ecx, 0
    jmp .print_8

.carry_8:
    mov ecx, 1

.print_8:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov dword ptr [rsp - 4], 3
    bts dword ptr [rsp - 4], 2
    mov edx, 2
    mov esi, 3
    jc .carry_9

    mov ecx, 0
    jmp .print_9

.carry_9:
    mov ecx, 1

.print_9:
    movabs rdi, offset .L.str.1
    mov r8d, dword ptr [rsp - 4]
    mov al, 0
    call printf

    mov dword ptr [rsp - 4], 3
    btr dword ptr [rsp - 4], 1
    mov edx, 1
    mov esi, 3
    jc .carry_10

    mov ecx, 0
    jmp .print_10

.carry_10:
    mov ecx, 1

.print_10:
    movabs rdi, offset .L.str.1
    mov r8d, dword ptr [rsp - 4]
    mov al, 0
    call printf

    mov dword ptr [rsp - 4], 3
    btc dword ptr [rsp - 4], 0
    mov edx, 0
    mov esi, 3
    jc .carry_11

    mov ecx, 0
    jmp .print_11

.carry_11:
    mov ecx, 1

.print_11:
    movabs rdi, offset .L.str.1
    mov r8d, dword ptr [rsp - 4]
    mov al, 0
    call printf

    mov r8d, 3
    btc r8d, 0
    mov edx, 0
    mov esi, 3
    jc .carry_12

    mov ecx, 0
    jmp .print_12

.carry_12:
    mov ecx, 1

.print_12:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov r8d, 3
    bts r8d, 1
    mov edx, 1
    mov esi, 3
    jc .carry_13

    mov ecx, 0
    jmp .print_13

.carry_13:
    mov ecx, 1

.print_13:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov r8d, 3
    btr r8d, 2
    mov edx, 2
    mov esi, 3
    jc .carry_14

    mov ecx, 0
    jmp .print_14

.carry_14:
    mov ecx, 1

.print_14:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov r8d, 3
    btc r8d, 8
    mov edx, 8
    mov esi, 3
    jc .carry_15

    mov ecx, 0
    jmp .print_15

.carry_15:
    mov ecx, 1

.print_15:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov r8d, 2
    bt r8d, 33
    mov edx, 33
    mov esi, 2
    jc .carry_16

    mov ecx, 0
    jmp .print_16

.carry_16:
    mov ecx, 1

.print_16:
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov r8, 2
    bt r8, 1
    mov edx, 1
    mov esi, 2
    jc .carry_17

    mov ecx, 0
    jmp .print_17

.carry_17:
    mov ecx, 1

.print_17:
    movabs rdi, offset .L.str.2
    mov al, 0
    call printf

    add rsp, 4
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "bt %d %d: CF = %d\n"
    .size   .L.str, 19
.L.str.1:
    .asciz  "bt %d %d: CF = %d, value after = %d\n"
    .size   .L.str.1, 37
.L.str.2:
    .asciz  "bt %lld %d: CF = %d\n"
    .size   .L.str.2, 21
.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 3
