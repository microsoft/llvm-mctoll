// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.5 == 1.5 = 1
// CHECK-NEXT: 1.5 == 0.0 = 0
// CHECK-NEXT: 1.5 == 1.5 = 1
// CHECK-NEXT: 1.5 == 0.0 = 0
// CHECK-NEXT: 1.5 == 1.5 = 1
// CHECK-NEXT: 1.5 == 0.0 = 0
// CHECK-NEXT: 1.5 == 1.5 = 1
// CHECK-NEXT: 1.5 == 0.0 = 0
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cmpss-cmpsd.s"

.p2align    4, 0x90
.type    cmpss_rr,@function
cmpss_rr:                                   # @cmpss_rr
    ucomiss xmm0, xmm1
    jnz .ne_ss_rr
    jp .ne_ss_rr
    jc .ne_ss_rr

    mov rax, 1
    ret

.ne_ss_rr:
    mov rax, 0
    ret

.p2align    4, 0x90
.type    cmpsd_rr,@function
cmpsd_rr:                                   # @cmpsd_rr
    ucomisd xmm0, xmm1
    jnz .ne_sd_rr
    jp .ne_sd_rr
    jc .ne_sd_rr

    mov rax, 1
    ret

.ne_sd_rr:
    mov rax, 0
    ret

.p2align    4, 0x90
.type    cmpss_rm,@function
cmpss_rm:                                   # @cmpss_rm
    ucomiss xmm0, [rdi]
    jnz .ne_ss_rm
    jp .ne_ss_rm
    jc .ne_ss_rm

    mov rax, 1
    ret

.ne_ss_rm:
    mov rax, 0
    ret

.p2align    4, 0x90
.type    cmpsd_rm,@function
cmpsd_rm:                                   # @cmpsd_rm
    ucomisd xmm0, [rdi]
    jnz .ne_sd_rm
    jp .ne_sd_rm
    jc .ne_sd_rm

    mov rax, 1
    ret

.ne_sd_rm:
    mov rax, 0
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val]
    call cmpsd_rr
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val.1]
    call cmpsd_rr
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.2]
    call cmpss_rr
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.3]
    call cmpss_rr
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    # rm comparisons
    movsd xmm0, [.L.val]
    movabs rdi, offset .L.val
    call cmpsd_rm
    movsd xmm1, [.L.val]
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movsd xmm0, [.L.val]
    movabs rdi, offset .L.val.1
    call cmpsd_rm
    movsd xmm1, [.L.val.1]
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movss xmm0, [.L.val.2]
    movabs rdi, offset .L.val.2
    call cmpss_rm
    movss xmm1, [.L.val.2]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    movss xmm0, [.L.val.2]
    movabs rdi, offset .L.val.3
    call cmpss_rm
    movss xmm1, [.L.val.3]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    mov rdi, offset .L.str
    mov rsi, rax
    mov al, 2
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%2$.1f == %3$.1f = %1$d\n"
    .size   .L.str, 11

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
.L.val.1:
    .quad 0x0000000000000000 # double 0.0
.L.val.2:
    .float 1.5
.L.val.3:
    .float 0.0
