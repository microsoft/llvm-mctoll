// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK: 10 - (1 + CF) = 9
// CHECK: 10 - (1 + CF) = 8
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-setl.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    # 64 bit operations
    mov rax, 1
    xor rsi, rsi
    add rsi, 10 # set cf = 0
    sbb rsi, rax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov rax, 1
    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb rsi, rax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 32 bit operations
    mov eax, 1
    xor rsi, rsi
    add esi, 10 # set cf = 0
    sbb esi, eax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov eax, 1
    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb esi, eax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 16 bit operations
    mov ax, 1
    xor rsi, rsi
    add si, 10 # set cf = 0
    sbb si, ax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov ax, 1
    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb si, ax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 8 bit operations
    mov al, 1
    xor rsi, rsi
    add sil, 10 # set cf = 0
    sbb sil, al
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov al, 1
    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb sil, al
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # rm instructions
    # 64 bit operations
    xor rsi, rsi
    add rsi, 10 # set cf = 0
    sbb rsi, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb rsi, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 32 bit operations
    xor rsi, rsi
    add esi, 10 # set cf = 0
    sbb esi, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb esi, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 16 bit operations
    xor rsi, rsi
    add si, 10 # set cf = 0
    sbb si, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb si, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # 8 bit operations
    xor rsi, rsi
    add sil, 10 # set cf = 0
    sbb sil, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rsi, rsi
    mov sil, 255
    add sil, 11 # set cf = 1
    sbb sil, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "10 - (1 + CF) = %d\n"
    .size   .L.str, 20
.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 1
