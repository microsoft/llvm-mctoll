// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0xffffffffffffffff0000000000000000
// CHECK-NEXT: 0x00000000ffffffff00000000ffffffff
// CHECK-NEXT: 0xffffffffffffffff0000000000000000
// CHECK-NEXT: 0x00000000ffffffff00000000ffffffff
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-unpcklpd.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 16

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    unpcklpd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    unpcklps xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    unpcklpd xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    unpcklps xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    add rsp, 16
    xor rax, rax
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "0x%016llx%016llx\n"
    .size   .L.str, 6

.section    .rodata.cst16,"aM",@progbits,16
.align 16
.L.val:
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff
.L.val.1:
    .quad 0x0000000000000000
    .quad 0x0000000000000000
