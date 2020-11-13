# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d  -debug %t.o 2>&1 | FileCheck %s

# CHECK: ARMEliminatePrologEpilog start
# CHECK: Frame Objects:
# CHECK-NOT: $sp = STMDB_UPD %SP
# CHECK-NOT: LDMIA $sp, 14, $noreg,
# CHECK: ARMEliminatePrologEpilog end

# test stm ldm with no frame
        .global test3
        .type test3, %function
test3:
        stmdb r13!, {r0-r3}
        stmdb r13!, {r4-r12,r13,r14}

        mov r3, #0
        mov r0,r3

        ldmia r13, {r4-r11, r13, r15}
        .size    test3, .-test3
