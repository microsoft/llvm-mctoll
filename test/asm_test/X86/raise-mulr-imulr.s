// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1230, overflow = 0 << 64, CF = 0
// CHECK: 492, rest = 0 << 32, CF = 0
// CHECK: 65534, rest = 1 << 16, CF = 1
// CHECK: -10, overflow = -1 << 64, CF = 0
// CHECK: -492, rest = -1 << 32, CF = 0
// CHECK: 2, rest = 65535 << 16, CF = 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-mulr-imulr.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    xor ecx, ecx
    mov rax, 10
    mov rdi, 123
    mul rdi
    # set cl = 1 if CF is set
    setc cl
    mov rsi, rax
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor ecx, ecx
    mov eax, 4
    mov edi, 123
    mul edi
    # set cl = 1 if CF is set
    setc cl
    mov esi, eax
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    xor ecx, ecx
    mov eax, 2
    mov edi, 0xffff
    mul di
    # set cl = 1 if CF is set
    setc cl
    # ignore bits we're not interested in
    and edx, 0xffff
    and esi, 0xffff
    mov esi, eax
    movabs rdi, offset .L.str.2
    mov al, 0
    call printf

    xor ecx, ecx
    mov rax, 10
    mov rdi, -1
    imul rdi
    # set cl = 1 if CF is set
    setc cl
    mov rsi, rax
    movabs rdi, offset .L.str.3
    mov al, 0
    call printf

    xor ecx, ecx
    mov eax, -4
    mov edi, 123
    imul edi
    # set cl = 1 if CF is set
    setc cl
    mov esi, eax
    movabs rdi, offset .L.str.4
    mov al, 0
    call printf

    xor ecx, ecx
    mov ax, 0x7fff
    mov di, -2
    imul di
    # set cl = 1 if CF is set
    setc cl
    # ignore bits we're not interested in
    and edx, 0xffff
    and esi, 0xffff
    mov esi, eax
    movabs rdi, offset .L.str.5
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%llu, overflow = %llu << 64, CF = %d\n"
    .size   .L.str, 10
.L.str.1:
    .asciz  "%u, rest = %u << 32, CF = %d\n"
    .size   .L.str.1, 10
.L.str.2:
    .asciz  "%u, rest = %u << 16, CF = %d\n"
    .size   .L.str.2, 10

.L.str.3:
    .asciz  "%lld, overflow = %lld << 64, CF = %d\n"
    .size   .L.str.3, 10
.L.str.4:
    .asciz  "%d, rest = %d << 32, CF = %d\n"
    .size   .L.str.4, 10
.L.str.5:
    .asciz  "%d, rest = %d << 16, CF = %d\n"
    .size   .L.str.5, 10
