// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0x00ffffffffffffffffffffffffffffff
// CHECK-NEXT: 0x0000ffffffffffffffffffffffffffff
// CHECK-NEXT: 0x00000000ffffffffffffffffffffffff
// CHECK-NEXT: 0x0000000000000000ffffffffffffffff
// CHECK-NEXT: 0x00ffffffffffffffffffffffffffffff
// CHECK-NEXT: 0x0000ffffffffffffffffffffffffffff
// CHECK-NEXT: 0x00000000ffffffffffffffffffffffff
// CHECK-NEXT: 0x0000000000000000ffffffffffffffff
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-pcmp.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    sub rsp, 16

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pcmpeqb xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pcmpeqw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pcmpeqd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pcmpeqq xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    # rm
    movdqa xmm0, [.L.val]
    pcmpeqb xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pcmpeqw xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pcmpeqd xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pcmpeqq xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, QWORD PTR [rsp + 8]
    mov rdx, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    add rsp, 16
    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "0x%016llx%016llx\n"
    .size   .L.str, 18

.section    .rodata.cst16,"aM",@progbits,16
.align 16
.L.val:
    .quad 0xabababababababab
    .quad 0x00ff00ffff123123
.L.val.1:
    .quad 0xabababababababab
    .quad 0xffff00ffff123123
