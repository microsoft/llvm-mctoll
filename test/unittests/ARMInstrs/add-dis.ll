; ModuleID = 'add.o'
source_filename = "add.o"
target datalayout = "e-m:e-p:32:32-i64:64-v128:64:128-a:0:32-n32-S64"

define i32 @funcAddReg(i32 %arg.1, i32 %arg.2) {
  %stack.3 = alloca i32
  %stack.4 = alloca i32
  %stack.5 = alloca i32
  %stack.6 = alloca i32
  %1 = add i32 %arg.2, 0
  %2 = add i32 %arg.1, 0
  store i32 %1, i32* %stack.3
  store i32 %2, i32* %stack.4
  %3 = load i32, i32* %stack.3
  %4 = load i32, i32* %stack.4
  %5 = add i32 %3, %4
  store i32 %1, i32* %stack.5
  store i32 %2, i32* %stack.6
  ret i32 %5
}
