// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d  -debug %t.o 2>&1 | FileCheck %s
// CHECK: ARMArgumentRaiser start
// CHECK: $r0 = MOVr %stack.1
// CHECK-NEXT: $r1 = MOVr %stack.2
// CHECK-NEXT: $r2 = MOVr %stack.3
// CHECK-NEXT: $r3 = MOVr %stack.4
// CHECK-NEXT: LDRi12 %stack.7
// CHECK-NEXT: LDRi12 %stack.6
// CHECK-NEXT: LDRi12 %stack.5
// CHECK: define i32 @func(i32 %arg.1, i32 %arg.2, i32 %arg.3, i32 %arg.4, i32 %arg.5, i32 %arg.6, i32 %arg.7) {
// CHECK: ARMArgumentRaiser end

long func(int a, long b, int c, long d, int e, long f, int g) {
  return a + b + c + d + e + f + g;
}
