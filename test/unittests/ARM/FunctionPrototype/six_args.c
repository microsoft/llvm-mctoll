// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s
// CHECK: ARMFunctionPrototype start.
// CHECK: i32 @func(i32 %0, i32 %1, i32 %2, i32 %3, i32 %4, i32 %5)
// CHECK: ARMFunctionPrototype end.
long func(int a, long b, int c, long d, int e, long f) {
  return a + b + c + d + e + f;
}
