// REQUIRES: system-linux
// RUN: clang --target=x86_64-linux -o exec %s
// RUN: llvm-mctoll -d exec --filter-functions-file=%p/filters-exec.txt
// RUN: cat exec-dis.ll | FileCheck %s
// CHECK: declare dso_local i32 @func2(i32, i32)
// CHECK: declare dso_local void @func4(i32)
// CHECK: declare dso_local i32 @func5()
// CHECK: define dso_local i32 @func1(i32 %arg1, i32 %arg2)
// CHECK: define dso_local i32 @func3(i32 %arg1, i32 %arg2)
// CHECK: define dso_local i32 @main()

int func1(int a, int b) { return a + b; }

int func2(int a, int b) { return a - b; }

int func3(int a, int b) { return a * b; }

void func4(int a) { a * 4; }

int func5(void) { return 0; }

int main() {
  int a, b, c;
  a = 5;
  b = 2;
  c = func1(a, b);
  c = func2(c, a);
  c = func3(c, b);
  func4(c);

  return func5();
}
