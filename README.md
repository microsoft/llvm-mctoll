# Introduction
Tool to statically (AOT) translate binaries to LLVM IR.

A tool to raise (or lift) compiled binaries to LLVM IR.

The implementation uses disassembly functionality implemented in
llvm-objdump.

# Getting Started (Linux/Mac)
## Building as part of LLVM tree

1.  `mkdir $PWD/src && mkdir -p $PWD/build/llvm && cd src`
2.  `git clone https://github.com/llvm-mirror/llvm && pushd llvm && git checkout master && popd`
3.  `pushd llvm/tools && git clone https://github.com/llvm-mirror/clang && git checkout master && popd`
4.  `pushd llvm/tools && git clone https://github.com/Microsoft/llvm-mctoll && git checkout master && popd`
7.  `cd ../build/llvm`
7.  Run cmake command that you usually use to build llvm
8.  Run `make llvm-mctoll` or `ninja llvm-mctoll`

## Building as standalone project (not as part of LLVM tree)
(**NOTE** : _Support for this needs to be updated. Please build llvm-mctoll as part of LLVM tree as described above_.)

The source files of this project include LLVM target-specific headers
from the LLVM source directory and LLVM build directory. Hence LLVM
sources need to be downloaded and built. At least, the following LLVM
targets need to be built so that all dependencies of llvm-mctoll are
available prior creating build files for llvm-mctoll (i.e., prior to
running `cmake` on llvm-mctoll tree).

   * llc
   * llvm-objdump
   * llvm-config

Building the targets llc and llvm-objdump will build all the necessary
libraries and include files to enable building of llvm-mctoll.

At present llvm-mctoll is being developed to handle X86_64 and ARM
binaries. So the above targets need to be built at least for these two
targets.

CMake script of llvm-mctoll uses `llvm-config` from the build tree to
discover the following information of the LLVM build used to build
llvm-mctoll.

   * assertion mode,
   * location of build and object directories,
   * location of LLVM source directory
   * compiler flags to be used,
   * location of cmake script directory

`llvm-config` from the LLVM build directory needs to be specified in the
cmake command that creates build files for llvm-mctoll.

If you also want to run the tests for llvm-mctoll, the following
additional dependencies from LLVM need to be built:

   * clang
   * count
   * not
   * FileCheck

Following assumes that llvm build dir is `<llvm-build-dir>` and an
install directory `<install-dir>` of your choice.

1.  `mkdir $PWD/src; mkdir -p $PWD/build/llvm-mctoll; cd src`
2.  `git clone TODO`
3.  `cd ../build/llvm-mctoll`
4.  Run cmake command as follows

    `cmake -G ["Unix Makefiles"|"Ninja"] -DLLVM_CONFIG_PATH=<llvm-build-dir>/bin/llvm-config -DCMAKE_INSTALL_PREFIX=<install-dir> ../../src/rawbits/llvm-mctoll`

5.  Run `make` or `ninja`. Resulting binary `llvm-mctoll` is in current directory.
6.   (Optional) Run `make install` or `ninja install`


# Usage instructions:

`llvm-mctoll -d <binary>`

or

To print debug output:

`llvm-mctoll -d -print-after-all <binary>`

To view Pass:
`llvm-mctoll -d -debug-pass=Structure <binary>`

# Current Status

The tool is currently able to raise Linux x86_64 shared libraries and executables with `printf` calls.

TODO :
1. Cleanup llvm-objdump related functionality that is not relevant to this tool.

# Build and Test

Run the tests by invoking 'make check-mctoll' or 'ninja check-mctoll'

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) 
declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR 
appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact 
opencode@microsoft.com with any additional questions or comments.

