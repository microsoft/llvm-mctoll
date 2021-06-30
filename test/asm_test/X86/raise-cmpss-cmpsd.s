// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0xffffffffffffffff
// CHECK-NEXT: 0x0000000000000000
// CHECK-NEXT: 0xffffffffffffffff
// CHECK-NEXT: 0x0000000000000000
// CHECK-NEXT: 0x00000000ffffffff
// CHECK-NEXT: 0x0000000000000000
// CHECK-NEXT: 0x00000000ffffffff
// CHECK-NEXT: 0x0000000000000000
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cmpss-cmpsd.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val]
    cmpeqsd xmm0, xmm1
    movsd QWORD PTR [rsp], xmm0
    mov rsi, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movsd xmm0, [.L.val.1]
    movsd xmm1, [.L.val]
    cmpeqsd xmm0, xmm1
    movsd QWORD PTR [rsp], xmm0
    mov rsi, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movsd xmm0, [.L.val]
    cmpeqsd xmm0, [.L.val]
    movsd QWORD PTR [rsp], xmm0
    mov rsi, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movsd xmm0, [.L.val]
    cmpeqsd xmm0, [.L.val.1]
    movsd QWORD PTR [rsp], xmm0
    mov rsi, QWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    // float operations
    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.2]
    cmpeqss xmm0, xmm1
    movss DWORD PTR [rsp], xmm0
    mov esi, DWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movss xmm0, [.L.val.1]
    movss xmm1, [.L.val.2]
    cmpeqss xmm0, xmm1
    movss DWORD PTR [rsp], xmm0
    mov esi, DWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movss xmm0, [.L.val.2]
    cmpeqss xmm0, [.L.val.2]
    movss DWORD PTR [rsp], xmm0
    mov esi, DWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    movss xmm0, [.L.val.2]
    cmpeqss xmm0, [.L.val.1]
    movss DWORD PTR [rsp], xmm0
    mov esi, DWORD PTR [rsp]
    mov rdi, offset .L.str
    mov al, 0
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "0x%016llx\n"
    .size   .L.str, 11

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
.L.val.1:
    .quad 0x0000000000000000 # double 0.0
.L.val.2:
    .float 1.5
