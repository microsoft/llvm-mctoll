// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0xababababababababcdcdcdcdcdcdcdcd
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
    movdqa xmm1, xmm0
    movdqu [rsp], xmm1
    mov rsi, QWORD PTR [rsp]
    mov rdx, QWORD PTR [rsp + 8]
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
    .quad 0xcdcdcdcdcdcdcdcd
