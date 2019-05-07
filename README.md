# Introduction
This tool statically (AOT) translates (or raises) binaries to LLVM IR.

# Getting Started (Linux)
## Building as part of LLVM tree

1.  `mkdir $PWD/src && mkdir -p $PWD/build/llvm && cd src`
2.  `git clone https://github.com/llvm-mirror/llvm && pushd llvm && git checkout master && popd`
3.  `pushd llvm/tools && git clone https://github.com/llvm-mirror/clang && git checkout master && popd`
4.  `pushd llvm/tools && git clone https://github.com/Microsoft/llvm-mctoll && git checkout master && popd`
5.  `cd ../build/llvm`
6.  Run cmake command to create build files (make or ninja) with default build type (Debug).

     Support for X86-64 and ARM raisers will be built into the tool based on the LLVM build targets. There is no interdependency. Consequently,  support to raise only X86-64 binaries is built during X86-only LLVM builds; support to raise only ARM binaries is built during ARM-only LLVM builds. The tool is not built during an LLVM build with targets that do not include either X86 or ARM.

    For e.g., either of the following `cmake` commands is known to build the tool and its dependencies.

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm> </full/path/to/github/src/llvm> -DLLVM_TARGETS_TO_BUILD="`*TARGET_ARCH*`"`

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm> </full/path/to/github/src/llvm>`

     The corresponding `cmake` commands known to work for Release builds are as follows:

     `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm> </full/path/to/github/src/llvm> -DLLVM_TARGETS_TO_BUILD="`*TARGET_ARCH*`" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_DUMP=ON -DLLVM_ENABLE_ASSERTIONS=ON`

    `cmake -G "Ninja" -DCMAKE_INSTALL_PREFIX=</full/path/to/github/install/llvm> </full/path/to/github/src/llvm> -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_DUMP=ON -DLLVM_ENABLE_ASSERTIONS=ON`

    You may also use the option `-G "Unix Makefiles"` instead of `-G "Ninja"`.

7.  Run `make llvm-mctoll` or `ninja llvm-mctoll`

#### _Note_ :
1. The current tip of llvm-mctoll is tested using the commits recorded in LLVMVersion.txt. Make sure the corresponding repos used in your build correspond to those listed.

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
