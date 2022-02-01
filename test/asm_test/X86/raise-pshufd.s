// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0xaaaaaaaabbbbbbbbccccccccdddddddd
// CHECK-NEXT: 0xddddddddccccccccbbbbbbbbaaaaaaaa
// CHECK-NEXT: 0xaaaaaaaabbbbbbbbaaaaaaaabbbbbbbb
// CHECK-NEXT: 0xaaaaaaaabbbbbbbbccccccccdddddddd
// CHECK-NEXT: 0xddddddddccccccccbbbbbbbbaaaaaaaa
// CHECK-NEXT: 0xaaaaaaaabbbbbbbbaaaaaaaabbbbbbbb
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
    pshufd xmm0, xmm1, 0xe4 # = 11 10 01 00
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pshufd xmm0, xmm1, 0x1b # = 00 01 10 11
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pshufd xmm0, xmm1, 0x44 # = 01 00 01 00
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pshufd xmm0, [.L.val.1], 0xe4 # = 11 10 01 00
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pshufd xmm0, [.L.val.1], 0x1b # = 00 01 10 11
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pshufd xmm0, [.L.val.1], 0x44 # = 01 00 01 00
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
    .quad 0xaaaaaaaabbbbbbbb
    .quad 0xccccccccdddddddd
