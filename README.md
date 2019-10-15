# Introduction

This tool statically (AOT) translates (or raises) binaries to LLVM IR.

# Current Status

The tool is capable of raising X86-64 and Arm32 Linux/ELF libraries and executables to LLVM IR.
Windows, OS X and C++ support need to be added. At this time X86-64 support is more mature than Arm32.

Development and testing are done on Ubuntu 18.04 and it's expected that Ubuntu 16.04, 17.04 and 17.10 work. The tool is also known to build and run all tests successfully on CentOS 7.5. The tool builds on OS X and Windows and is capable of raising Linux binaries on both platforms.

| Triple | VarArgs | FuncProto | StackFrame | JumpTables | SharedLibs | C++ |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| x86_64-linux | X | X | X | X | X | |
| arm-linux | X | X | X | X | X | | 

* VarArgs: function calls with variable arguments (such as printf)
* FuncProto: function prototype discovery
* StackFrame: stack frame abstraction
* JumpTables: switch statements with jump tables
* SharedLibs: shared libraries
* C++: vtables and name mangling

## Known Issues

SIMD instructions such as SSE, AVX, Neon cannot be raised at this time. For X86-64 you can sometimes work around this issue by compiling the binary to raise with SSE disabled (`clang -mno-sse`). 

Most testing is done using binaries compiled for Linux using LLVM. We have done only limited testing with GCC compiled code.

# Getting Started

There are no dependencies outside of LLVM to build `llvm-mctoll`. The following instructions assume you will build LLVM with [Ninja](https://ninja-build.org).

Support for raising X86-64 and Arm32 binaries is enabled by building LLVM's X86 and ARM targets. The tool is not built unless one of the X86 or ARM LLVM targets are built.

## Building as part of the LLVM tree

1. On Linux and OS X build from a command prompt such as a bash shell. On Windows build from an `x64 Native Tools Command Prompt`. See [LLVM's Visual Studio guide](https://llvm.org/docs/GettingStartedVS.html) for help.

2. Clone the LLVM and mctoll git repositories

```sh
git clone --depth 100 -b master https://github.com/llvm/llvm-project.git
cd llvm-project && git clone -b master https://github.com/microsoft/llvm-mctoll.git llvm/tools/llvm-mctoll
```

3. Build LLVM with ARM and X86 targets and assertions enabled (See [LLVM CMake Variables](https://llvm.org/docs/CMake.html#frequently-used-cmake-variables))

```sh
mkdir build && cd build
cmake -G "Ninja" -DLLVM_TARGETS_TO_BUILD="X86;ARM" -DLLVM_ENABLE_PROJECTS=clang -DLLVM_ENABLE_ASSERTIONS=true -DCMAKE_BUILD_TYPE=Release ../llvm
ninja llvm-mctoll
```

4. Run the unit tests (Linux only)
```
ninja check-mctoll
```

## The version of LLVM to build against

The commit recorded in `LLVMVersion.txt` is the supported version of LLVM to build against. Make sure the tip of the `llvm-project` repo you use to build corresponds to the commit listed there.

# Usage

| Command | Description |
| --- | --- |
| `-d <binary>` | Generate LLVM IR for a binary and place the result in `<binary>-dis.ll` |
| `--filter-functions-file=<file>` | Text file with C functions to exclude or include during raising |
| `-print-after-all` | Print the LLVM IR after each pass of the raiser |

## Raising a binary to LLVM IR

This is what you came here for :-). Please [file an issue](https://github.com/microsoft/llvm-mctoll/issues) if you find a problem.
```
llvm-mctoll -d a.out
```

## Raising specific functions in a binary

You can specify the C functions to include or exclude during raising with the `--filter-functions-file` option.

```
llvm-mctoll -d --filter-functions-file=restrict.txt a.out
```

Provide a plain text file with `exclude-functions` and `include-functions` sections. Inside each section list the file and function prototype seperated by a colon. Use [LLVM IR function types](https://llvm.org/docs/LangRef.html#function-type) when defining the return and argument types for a function prototype. Here is a simple example.

```
; exclude `int bar(int)` defined in a.out
exclude-functions {
  a.out:i32 bar(i32)   
}

; include `int foo(void)` defined in a.out
include-functions {
  a.out:i32 foo(void)   
}
```

## Debugging the raiser

If you build `llvm-mctoll` with assertions enabled you can print the LLVM IR after each pass of the raiser to assist with debugging.
```
llvm-mctoll -d -print-after-all a.out
```

## Checking a translation is correct

The easiest way to check the raised LLVM IR `<binary>-dis.ll` is correct is to compile the IR to an executable using `clang` and run the resulting executable. The tests in the repository follow this methodology. 

# Acknowledgements

Please use the following reference when citing `llvm-mctoll` in your work:

* `Raising Binaries to LLVM IR with MCTOLL (WIP), S. Bharadwaj Yadavalli and Aaron Smith, LCTES 2019`

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA)
declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR
appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all
repos using our CLA.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact
opencode@microsoft.com with any additional questions or comments.
