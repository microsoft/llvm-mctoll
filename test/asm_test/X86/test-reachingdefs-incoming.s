// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 42.5
// CHECK: 42.5
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "test-reachingdefs-incoming.s"

.p2align    4, 0x90
.type    test_fp,@function
test_fp:
    movaps xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf
    ret

.p2align    4, 0x90
.type    reaching_defs_fp,@function
reaching_defs_fp:
    sub rsp, 8
    movsd xmm0, [.LCPI2_1]
    mov rax, 0
    cmp rax, 0
    je .rd_fp_call_test

    movsd xmm0, [.LCPI2_0]

.rd_fp_call_test:
    call test_fp

    add rsp, 8
    ret

.p2align    4, 0x90
.type    test_vec,@function
test_vec:
    pand xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf
    ret

.p2align    4, 0x90
.type    reaching_defs_vec,@function
reaching_defs_vec:
    sub rsp, 8
    movsd xmm0, [.LCPI2_1]
    pand xmm0, xmm0
    mov rax, 0
    cmp rax, 0
    je .rd_vec_call_test

    movsd xmm0, [.LCPI2_0]
    pand xmm0, xmm0

.rd_vec_call_test:
    call test_vec

    add rsp, 8
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    call reaching_defs_fp
    call reaching_defs_vec
    xor rax, rax
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%.1f\n"
    .size   .L.str, 6

.section    .rodata.cst8,"aM",@progbits,8
.LCPI2_0:
    .long   0x0000000000000000              # double 0.0
.LCPI2_1:
    .quad   0x4045400000000000              # double 42.5
