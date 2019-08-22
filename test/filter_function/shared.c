// RUN: clang -o shared.so %s -shared -fPIC
// RUN: llvm-mctoll -d shared.so --filter-functions-file=%p/filters-shared.txt
// RUN: cat shared-dis.ll | FileCheck %s
// CHECK: declare dso_local i32 @func2(i32, i32)
// CHECK: define dso_local i32 @func1(i32 %arg1, i32 %arg2)
// CHECK: define dso_local i32 @func3(i32 %arg1, i32 %arg2)

int func1(int a, int b) { return a + b; }

int func2(int a, int b) { return a - b; }

int func3(int a, int b) {
  int c, d;
  c = func1(a, b);
  d = func2(a, b);
  return c * d;
}
