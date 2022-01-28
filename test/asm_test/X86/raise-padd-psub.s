// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0x010000ffffffff00010000ffffffff00
// CHECK-NEXT: 0x020000ffffff0000020000ffffff0000
// CHECK-NEXT: 0x020100ff00000000020100ff00000000
// CHECK-NEXT: 0x02010100000000000201010000000000
// CHECK-NEXT: 0xfeffff00000000fffeffff00000000ff
// CHECK-NEXT: 0xfdffff000000fffffdffff000000ffff
// CHECK-NEXT: 0xfdfeff00fffffffffdfeff00ffffffff
// CHECK-NEXT: 0xfdfefefffffffffffdfefeffffffffff
// CHECK-NEXT: 0x010000ffffffff00010000ffffffff00
// CHECK-NEXT: 0x020000ffffff0000020000ffffff0000
// CHECK-NEXT: 0x020100ff00000000020100ff00000000
// CHECK-NEXT: 0x02010100000000000201010000000000
// CHECK-NEXT: 0xfeffff00000000fffeffff00000000ff
// CHECK-NEXT: 0xfdffff000000fffffdffff000000ffff
// CHECK-NEXT: 0xfdfeff00fffffffffdfeff00ffffffff
// CHECK-NEXT: 0xfdfefefffffffffffdfefeffffffffff
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-sse-binary-inst.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 16

    # add
    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    paddb xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    paddw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    paddd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    movdqa xmm1, [.L.val.1]
    paddq xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # sub
    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    psubb xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    psubw xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    psubd xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    movdqa xmm1, [.L.val.3]
    psubq xmm0, xmm1
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # memory referencing
    # add
    movdqa xmm0, [.L.val]
    paddb xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    paddw xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    paddd xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val]
    paddq xmm0, [.L.val.1]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # sub
    movdqa xmm0, [.L.val.2]
    psubb xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    psubw xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    psubd xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    movdqa xmm0, [.L.val.2]
    psubq xmm0, [.L.val.3]
    movdqu [rsp], xmm0
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
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
    .quad 0x00ffffffffffffff
    .quad 0x00ffffffffffffff
.L.val.1:
    .quad 0x0101010000000001
    .quad 0x0101010000000001
.L.val.2:
    .quad 0xff00000000000000
    .quad 0xff00000000000000
.L.val.3:
    .quad 0x0101010000000001
    .quad 0x0101010000000001
