// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.0
// CHECK: 2.0
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-sse-ret-types.s"

.p2align    4, 0x90
.type    test_vec_ret,@function
test_vec_ret:
    pand xmm0, xmm0
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    # check return type, pass directly to printf
    movsd xmm0, [.L.val]
    call test_vec_ret

    mov al, 1
    mov rdi, offset .L.str
    call printf

    movsd xmm0, [.L.val]
    call test_vec_ret

    # now execute a fp operation on the vecor value, which will require a cast
    movsd xmm1, [.L.val]
    addsd xmm0, xmm1

    mov al, 1
    mov rdi, offset .L.str
    call printf

    add rsp, 8
    xor rax, rax
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%.1f\n"
    .size   .L.str, 6

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff0000000000000 # double 1.0
