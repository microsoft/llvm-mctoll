// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 10
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-imul64rm.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    mov rsi, 1
    imul rsi, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d\n"
    .size   .L.str, 10

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0xA # int64_t 10
