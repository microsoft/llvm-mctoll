// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0xff112233ff556677ff99aabbffddeeff
// CHECK-NEXT: 0xff0e2233ff056677ff06aabbff01eeff
// CHECK-NEXT: 0xff0e0d0cff050607ff060504ff010100
// CHECK-NEXT: 0x000e0d0c4405060788060504cc010100
// CHECK-NEXT: 0x00110d0c4455060788990504ccdd0100
// CHECK-NEXT: 0x00112233445566778899aabbccddeeff
// CHECK-NEXT: 0xff112233ff556677ff060504ff010100
// CHECK-NEXT: 0xff0e2233ff056677ff060504ff010100
// CHECK-NEXT: 0xff0e0d0cff050607ff060504ff010100
// CHECK-NEXT: 0xf00e0d0cf4050607f899aabbfcddeeff
// CHECK-NEXT: 0xf0110d0cf4550607f899aabbfcddeeff
// CHECK-NEXT: 0xf0112233f4556677f899aabbfcddeeff
// CHECK-NEXT: 0xff112233ff556677ff99aabbffddeeff
// CHECK-NEXT: 0xff0e2233ff056677ff06aabbff01eeff
// CHECK-NEXT: 0xff0e0d0cff050607ff060504ff010100
// CHECK-NEXT: 0x000e0d0c4405060788060504cc010100
// CHECK-NEXT: 0x00110d0c4455060788990504ccdd0100
// CHECK-NEXT: 0x00112233445566778899aabbccddeeff
// CHECK-NEXT: 0xff112233ff556677ff060504ff010100
// CHECK-NEXT: 0xff0e2233ff056677ff060504ff010100
// CHECK-NEXT: 0xff0e0d0cff050607ff060504ff010100
// CHECK-NEXT: 0xf00e0d0cf4050607f899aabbfcddeeff
// CHECK-NEXT: 0xf0110d0cf4550607f899aabbfcddeeff
// CHECK-NEXT: 0xf0112233f4556677f899aabbfcddeeff
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-sse-binary-inst.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 16

    # max
    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pmaxub xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pmaxuw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pmaxud xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # min
    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pminub xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pminuw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    pminud xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # signed
    # max
    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pmaxsb xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pmaxsw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pmaxsd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # min
    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pminsb xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pminsw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    pminsd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # mem referencing
    # max
    movdqa xmm0, [.L.val]
    pmaxub xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pmaxuw xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pmaxud xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # min
    movdqa xmm0, [.L.val]
    pminub xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pminuw xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    pminud xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # signed
    # max
    movdqa xmm0, [.L.val.2]
    pmaxsb xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    pmaxsw xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    pmaxsd xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # min
    movdqa xmm0, [.L.val.2]
    pminsb xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    pminsw xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    pminsd xmm0, [.L.val.3]
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
    .quad 0xff0e0d0cff050607
    .quad 0xff060504ff010100
.L.val.1:
    .quad 0x0011223344556677
    .quad 0x8899aabbccddeeff
.L.val.2:
    .quad 0xff0e0d0cff050607
    .quad 0xff060504ff010100
.L.val.3:
    .quad 0xf0112233f4556677
    .quad 0xf899aabbfcddeeff
