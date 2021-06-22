// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0
// CHECK: 1
// CHECK: 1
// CHECK: 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cmovbe.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    movabs rdi, offset .L.str
    mov rbx, 0x1
    mov rsi, 0x0
    mov rax, 0x1
    // set zf = 0, cf = 0
    cmp rax, 0x0 // 0x1 - 0x0 does not set ZF and has no overflow
    cmovbe rsi, rbx
    mov al, 0
    call printf

    movabs rdi, offset .L.str
    mov rbx, 0x1
    mov rsi, 0x0
    // set zf = 1, cf = 0
    cmp rsi, 0x0 // 0x0 - 0x0 sets ZF and has no overflow
    cmovbe rsi, rbx
    mov al, 0
    call printf

    movabs rdi, offset .L.str
    mov rbx, 0x1
    mov rsi, 0x0
    // set zf = 0, cf = 1
    mov al, 0xFF
    add al, 0xFF // 0xFF + 0xFF does not set ZF and has overflow
    cmovbe rsi, rbx
    mov al, 0
    call printf

    movabs rdi, offset .L.str
    mov rbx, 0x1
    mov rsi, 0x0
    // set zf = 1, cf = 1
    mov al, 0xFF
    add al, 0x1 // 0xFF + 0x1 = 0x00 sets ZF and has overflow
    cmovbe rsi, rbx
    mov al, 0
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d\n"
    .size   .L.str, 4
