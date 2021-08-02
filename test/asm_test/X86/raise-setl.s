// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: SETL: 1, SETNL: 0
// CHECK: SETL: 0, SETNL: 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-setl.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    xor rax, rax
    xor rbx, rbx

    # set SF
    or al, 0xff

    setl al
    setnl bl
    mov rsi, rax
    mov rdx, rbx
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # set OF and SF
    mov al, 0x7f
    add al, 1

    setl al
    setnl bl
    mov rsi, rax
    mov rdx, rbx
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "SETL: %d, SETNL: %d\n"
    .size   .L.str, 10
