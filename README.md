# Introduction
This tool statically (AOT) translates (or raises) binaries to LLVM IR.

# Getting Started (Linux)
## Building as part of LLVM tree

1.  `mkdir $PWD/src && mkdir -p $PWD/build/llvm-project && cd src`
2.  `git clone https://github.com/llvm/llvm-project && pushd llvm-project && git checkout master && popd`
4.  `pushd llvm-project/llvm/tools && git clone https://github.com/microsoft/llvm-mctoll && git checkout master && popd`
5.  `cd ../build/llvm-project`
6.  Run cmake command to create build files (make or ninja) with default build type (Debug).

     Support for X86-64 and ARM raisers will be built into the tool based on the LLVM build targets. There is no interdependency. Consequently,  support to raise only X86-64 binaries is built during X86-only LLVM builds; support to raise only ARM binaries is built during ARM-only LLVM builds. The tool is not built during an LLVM build with targets that do not include either X86 or ARM.

    For e.g., either of the following `cmake` commands is known to build the tool and its dependencies.

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm-project> </full/path/to/github/src/llvm-project/llvm> -DLLVM_ENABLE_PROJECTS=clang`

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm-project> </full/path/to/github/src/llvm-project/llvm> -DLLVM_TARGETS_TO_BUILD="`*TARGET_ARCH*`" -DLLVM_ENABLE_PROJECTS=clang` 

     The corresponding `cmake` commands known to work for Release builds are as follows:

     `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm-project> </full/path/to/github/src/llvm-project/llvm> -DLLVM_TARGETS_TO_BUILD="`*TARGET_ARCH*`" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_DUMP=ON -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_PROJECTS=clang`

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm-project> </full/path/to/github/src/llvm-project/llvm> -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_DUMP=ON -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_PROJECTS=clang`

    You may also use the option `-G "Unix Makefiles"` instead of `-G "Ninja"`.

7.  Run `make llvm-mctoll` or `ninja llvm-mctoll`

#### _Note_ :
1. The current tip of `llvm-mctoll` is tested using the tip of `llvm-project` repo recorded in LLVMVersion.txt. Make sure the tip of `llvm-project` repo used in your build corresponds to that listed.

## Usage

To generate LLVM IR for a binary:

`llvm-mctoll -d <binary>`

The raised result is generated as `<binary>-dis.ll`.

To check the correctness of `<binary>-dis.ll`
1. compile `<binary>-dis.ll` to an executable (or to a shared library if `<binary>` is a shared library) using `clang`.
2. run the resulting executable (or use the resulting shared library `<binary>-dis` in place of `<binary>`) to verify that its execution behavior is identical to that of the original `<binary>`.

Tests in the tool repository are written following the above described methodology.

To print debug output:

`llvm-mctoll -d -print-after-all <binary>`

## Control Functions to Raise in a Module

C functions to be excluded or included are listed in a file using the option:

`--restrict-functions-file=<filename-with-include-exclude-restrictions>`

The file will have text lines as follows
```
exclude-functions {
binary-name-1:function-1-prototype
binary-name-2:function-2-prototype
}

include-functions {
binary-name-3:function-3-prototype
binary-name-4:function-4-prototype
}
```

# Notes regarding function prototype specification in filter file:
1. `function-prototype` - which includes return type - expects only the argument types and not the associated arument variable names.
1. Currently, only LLVM primitive data types are supported.
1. Functions that do not have arguments are expected to use a single argument type `void`
1. A line starting with `;` is ignored.

## Build and Test

Run the tests by invoking `make check-mctoll` or `ninja check-mctoll`

At present, the development and testing are done on Ubuntu 18.04. It is expected that build and test would work on Ubuntu 16.04, 17.04 and 17.10.

The tool is also known to build and run tests successfully on CentOS 7.5.

# Current Status

At present, the tool is capable of raising Linux X86-64 and Arm32 shared libraries and executables with function calls that have variable arguments (such as printf) to LLVM IR.

Raising of C++ binaries needs to be added.

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA)
declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR
appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all
repos using our CLA.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact
opencode@microsoft.com with any additional questions or comments.
