# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all -debug %t.o 2>&1 | FileCheck %s

# CHECK: ARMEliminatePrologEpilog start
# CHECK: Frame Objects:
# CHECK-NOT: $r12 = MOVr $sp
# CHECK-NOT: $sp = STMDB_UPD $sp, 14
# CHECK-NOT: $r11 = SUBri $r12, 16, 14,
# CHECK-NOT: LDMDB $sp, 14,
# CHECK: ARMEliminatePrologEpilog end

# test stm ldm with frame
        .global test4
        .type test4, %function
test4:
        mov r12, r13
        stmdb r13!, {r0-r3}
        stmdb r13!, {r4-r12, r14}
        sub r11, r12, #16

        mov r3, #0
        mov r0,r3

        ldmdb r13, {r4-r11, r13, r15}
        .size test4, .-test4
