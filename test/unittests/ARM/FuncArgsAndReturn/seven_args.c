// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s
// CHECK: ARMArgumentRaiser start
// CHECK: LDRi12 %stack.7
// CHECK-NEXT: LDRi12 %stack.6
// CHECK-NEXT: LDRi12 %stack.5
// CHECK-NEXT: MOVr %stack.4
// CHECK-NEXT: MOVr %stack.3
// CHECK-NEXT: MOVr %stack.2
// CHECK-NEXT: MOVr %stack.1
// CHECK: ADDrr %stack.0
// CHECK: define i32 @func(i32 %arg.1, i32 %arg.2, i32 %arg.3, i32 %arg.4, i32 %arg.5, i32 %arg.6, i32 %arg.7) {
// CHECK: ARMArgumentRaiser end

long func(int a, long b, int c, long d, int e, long f, int g) {
  return a + b + c + d + e + f + g;
}
