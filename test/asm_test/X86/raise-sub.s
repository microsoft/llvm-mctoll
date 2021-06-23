// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 0
// CHECK-NEXT: 0
// CHECK-NEXT: 0
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-sub.s"

.p2align    4, 0x90
.type    sub8rr_zero,@function
sub8rr_zero:                                   # @sub8rr_zero
    xor rax, rax
    mov al, 8
    mov bl, 8
    sub al, bl

    // make sure zf is set, but not cf
    jnz .sub8rr_zero.fail
    jc .sub8rr_zero.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    ret

.sub8rr_zero.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    sub16rr_zero,@function
sub16rr_zero:                                   # @sub16rr_zero
    xor rax, rax
    mov ax, 8
    mov bx, 8
    sub ax, bx

    // make sure zf is set, but not cf
    jnz .sub16rr_zero.fail
    jc .sub16rr_zero.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    ret

.sub16rr_zero.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    sub16rm_zero,@function
sub16rm_zero:                                   # @sub16rm_zero
    sub rsp, 6
    xor rax, rax
    mov ax, 8
    push ax
    sub ax, [rsp]

    // make sure zf is set, but not cf
    jnz .sub16rm_zero.fail
    jc .sub16rm_zero.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    add rsp, 8
    ret

.sub16rm_zero.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    sub8rr,@function
sub8rr:                                   # @sub8rr
    xor rax, rax
    mov al, 8
    mov bl, 4
    sub al, bl

    // make sure neither zf nor cf are set
    jz .sub8rr.fail
    jc .sub8rr.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    ret

.sub8rr.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    sub16rr,@function
sub16rr:                                   # @sub16rr
    xor rax, rax
    mov ax, 8
    mov bx, 4
    sub ax, bx

    // make sure neither zf nor cf are set
    jz .sub16rr.fail
    jc .sub16rr.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    ret

.sub16rr.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    sub16rm,@function
sub16rm:                                   # @sub16rm
    sub rsp, 6
    xor rax, rax
    mov ax, 4
    push ax
    mov ax, 8
    sub ax, [rsp]

    // make sure neither zf nor cf are set
    jz .sub16rm.fail
    jc .sub16rm.fail

    movabs rdi, offset .L.str
    mov rsi, rax
    mov al, 0
    call printf
    add rsp, 8
    ret

.sub16rm.fail:
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    call sub8rr_zero
    call sub16rr_zero
    call sub16rm_zero
    call sub8rr
    call sub16rr
    call sub16rm

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d\n"
    .size   .L.str, 4
.L.str.1:
    .asciz  "Incorrect flags set\n"
    .size   .L.str.1, 21
