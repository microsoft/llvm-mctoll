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

To print debug output:

`llvm-mctoll -d -print-after-all <binary>`

## Build and Test

Run the tests by invoking 'make check-mctoll' or 'ninja check-mctoll'

# Current Status

The tool is currently able to raise Linux x86_64 and Arm32 shared libraries and executables with function calls that have variable 
arguments (such as printf) to LLVM IR.

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) 
declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR 
appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact 
opencode@microsoft.com with any additional questions or comments.

