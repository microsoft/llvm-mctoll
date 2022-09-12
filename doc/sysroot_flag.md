## Using --sysroot flag

--sysroot points to toolchain root. It is useful during development on a non-Linux machine to raise Linux binaries or on a Linux machine using a toolchain other than the one installed.

* On linux sysroot is "/"
* On MAC may show `xcrun --show-sdk-path`

### Cross-building Linux x86_64 and arm binaries

Instructions to build a minimal functional toolchain that may be used with `llvm-mctoll` are provided [here](https://github.com/sv99/llvm-mctoll-toolchains). These facilitate cross compilation of and raising of x86_64-linux-gnu and for arm-linux-gnueabihf targets. You may choose to create and use a toolchain of your choice.
```bash
# toolchain directory
# ~/toolchain/arm-linux-gnueabihf
# ~/toolchain/x86_64-linux-gnu
# clang must be built with ARM support!

# ELF 32-bit ARM Linux
clang --sysroot ~/toolchain/arm-linux-gnueabihf \
  -target arm-linux-gnueabihf -fuse-ld=lld \
  -o hello-arm -v hello.c
file helllo-arm

# ELF 64-bit x86_64 Linux
clang --sysroot ~/toolchain/x86_64-linux-gnu \
  -target x86_64-linux-gnu -fuse-ld=lld \
  -o hello-lin -v hello.c
file helllo-lin
```

The above has been tested to work on MacOS (and Linux).

### Raising Linux binary on a non-Linux host

Toolchains needs for successful parsing header file.

```c
# header-inc.h
#include <stdio.h>
```

```bash
# ELF 32-bit ARM Linux
llvm-mctoll --sysroot ~/toolchain/arm-linux-gnueabihf \
  -target arm-linux-gnueabihf -I header-inc.h \
  -debug -d hello-arm
# ELF 64-bit x86_64 Linux
lvm-mctoll --sysroot ~/toolchain/x86_64-linux-gnu \
  -target x86_64-linux-gnu -I header-inc.h \
  -debug -d hello-arm 
 ```

### Running Linux ARM binary using docker on a non-Linux development host

[multiarch/qemu-user-static](https://github.com/multiarch/qemu-user-static) is to enable
an execution of different multi-architecture containers

```bash
# prepare docker
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

```bash
# run x86_64-linux-gnu binary
docker run --rm -it -v $(pwd):/work amd64/ubuntu:20.04 /work/hello-linux

# run arm-linux-gnueabihf binary
docker run --rm -it -v $(pwd):/work arm32v7/ubuntu:20.04 /work/hello-arm
```