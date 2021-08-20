// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 256 == 256 = 1
// CHECK-NEXT: 255 == 256 = 0
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cmp.s"

.p2align    4, 0x90
.type    cmp64ri32,@function
cmp64ri32:
    cmp rdi, 256
    jne .ne
    mov rax, 1
    ret
.ne:
    mov rax, 0
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    mov rdi, 256
    call cmp64ri32
    mov rdx, rax
    mov rsi, 256
    mov rdi, offset .L.str
    mov al, 0
    call printf

    mov rdi, 255
    call cmp64ri32
    mov rdx, rax
    mov rsi, 255
    mov rdi, offset .L.str
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d == 256 = %d\n"
    .size   .L.str, 16
