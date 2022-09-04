## Using --sysroot flag

--sysroot points to toolchain root.

* On linux sysroot is "/"
* On MAC may show `xcrun --show-sdk-path`

### cross build linux and arm binary

On the [llvm-mctoll-toolchains](https://github.com/sv99/llvm-mctoll-toolchains) exists minimal working toolchain
for cross compilation for arm-linux-gnueabihf and x86_64-linux-gnu.

```bash
# toolchain directory
# ~/toolchain/arm-linux-gnueabihf
# ~/toolchain/x86_64-linux-gnu
# clang must be build with ARM support!

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

This worked on linux and MAC.

### raising binary

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

### run arm binary using docker

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