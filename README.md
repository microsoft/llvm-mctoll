# Introduction
This tool statically (AOT) translates (or raises) binaries to LLVM IR.

# Getting Started (Linux/Mac)
## Building as part of LLVM tree

1.  `mkdir $PWD/src && mkdir -p $PWD/build/llvm && cd src`
2.  `git clone https://github.com/llvm-mirror/llvm && pushd llvm && git checkout master && popd`
3.  `pushd llvm/tools && git clone https://github.com/llvm-mirror/clang && git checkout master && popd`
4.  `pushd llvm/tools && git clone https://github.com/Microsoft/llvm-mctoll && git checkout master && popd`
7.  `cd ../build/llvm`
7.  Run cmake command that you usually use to build llvm
8.  Run `make llvm-mctoll` or `ninja llvm-mctoll`

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

# Current Status

The tool is currently able to raise Linux x86_64 and Arm32 shared libraries and executables with function calls that have variable arguments (such as printf) to LLVM IR.

Support for code generated for `switch` statement needs to be added.

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

## License
LLVM is licensed under the [LLVM Release License](https://github.com/Microsoft/llvm-mctoll/blob/master/LICENSE)
