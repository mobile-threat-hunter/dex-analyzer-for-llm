# Linux sysroot builds

This directory contains helper files for building DexKit Linux binaries against
older Ubuntu runtime libraries.

The goal is to keep the generated `libdexkit.so` compatible with the target
distribution's glibc, libstdc++, and libgcc runtime. Do not add
`ppa:ubuntu-toolchain-r/test` to the sysroot: the compatibility target is the
toolchain shipped by the distribution itself. That PPA can upgrade runtime
packages such as `libstdc++6`, so the sysroot would no longer represent the
distribution-provided runtime.

Run the commands from the repository root. `build-linux-sysroot.sh` must run as
root because `debootstrap` creates device nodes and package metadata inside the
sysroot. If a sysroot or headers directory already exists, remove it first.

## Pack sysroot backups

After building a sysroot, it can be packed for backup or reuse. Replace the
path with the target sysroot that was built:

```bash
sudo tar -C .dexkit-sysroot/ubuntu-16.04-x86_64 \
  --exclude=./dev \
  --exclude=./proc \
  --exclude=./sys \
  --exclude=./run \
  --exclude=./tmp \
  --exclude=./var/tmp \
  -cJf .dexkit-sysroot/ubuntu-16.04-x86_64.tar.xz .
```

The GCC 10 headers directory can be packed without special excludes:

```bash
tar -C .dexkit-sysroot/gcc10-headers \
  -cJf .dexkit-sysroot/gcc10-headers.tar.xz .
```

To unpack a backup:

```bash
rm -rf .dexkit-sysroot/ubuntu-16.04-x86_64
mkdir -p .dexkit-sysroot/ubuntu-16.04-x86_64
tar -C .dexkit-sysroot/ubuntu-16.04-x86_64 \
  -xJf .dexkit-sysroot/ubuntu-16.04-x86_64.tar.xz

rm -rf .dexkit-sysroot/gcc10-headers
mkdir -p .dexkit-sysroot/gcc10-headers
tar -C .dexkit-sysroot/gcc10-headers \
  -xJf .dexkit-sysroot/gcc10-headers.tar.xz
```

## Ubuntu 20.04 target

Ubuntu 20.04 is the baseline C++20 build. Its sysroot includes GCC 10 headers
and libstdc++.

```bash
sudo env UBUNTU_CODENAME=focal \
  bash build-support/linux-sysroot/build-linux-sysroot.sh \
  .dexkit-sysroot/ubuntu-20.04-x86_64

SYSROOT="$PWD/.dexkit-sysroot/ubuntu-20.04-x86_64"

export CC="clang --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export CXX="clang++ --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export AR=llvm-ar
export RANLIB=llvm-ranlib
export LD=ld.lld

./gradlew :dexkit:cmakeBuild --console=plain
```

## Ubuntu 18.04 target

Ubuntu 18.04 has an older runtime, but it can use the GCC 10 C++ headers
for C++20 `std::span` and `std::string_view::starts_with` /
`std::string_view::ends_with`.

```bash
sudo env UBUNTU_CODENAME=bionic \
  bash build-support/linux-sysroot/build-linux-sysroot.sh \
  .dexkit-sysroot/ubuntu-18.04-x86_64

bash build-support/linux-sysroot/fetch-libstdcxx-headers.sh \
  .dexkit-sysroot/gcc10-headers

SYSROOT="$PWD/.dexkit-sysroot/ubuntu-18.04-x86_64"
GCC10_HEADERS="$PWD/.dexkit-sysroot/gcc10-headers/usr/include"
COMPAT_HEADER="$PWD/.dexkit-sysroot/compat/glibc-libstdcxx10-compat.h"

mkdir -p "$(dirname "$COMPAT_HEADER")"
cp build-support/linux-sysroot/glibc-libstdcxx10-compat.h "$COMPAT_HEADER"

export CC="clang --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export CXX="clang++ --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export AR=llvm-ar
export RANLIB=llvm-ranlib
export LD=ld.lld
export CFLAGS=
export CXXFLAGS="-nostdinc++ -isystem $GCC10_HEADERS/c++/10 -isystem $GCC10_HEADERS/x86_64-linux-gnu/c++/10 -include $COMPAT_HEADER"
export LDFLAGS="-Wl,--no-as-needed -lpthread"

./gradlew :dexkit:cmakeBuild --console=plain
```

`glibc-libstdcxx10-compat.h` undefines libstdc++ feature macros for pthread
clock APIs that are unavailable in the older glibc target.

`-lpthread` is needed for pre-2.34 glibc targets such as Ubuntu 18.04 because
pthread is still provided by a separate `libpthread.so.0` there. `--no-as-needed`
keeps `libpthread.so.0` in the dynamic dependencies even if the linker only sees
pthread usage indirectly through libstdc++.

`fetch-libstdcxx-headers.sh` downloads `libstdc++-10-dev` by parsing Ubuntu
`Packages.xz` indexes. It defaults to the focal repositories because GCC 10 is
the distro compiler there.

## Ubuntu 16.04 target

Ubuntu 16.04 is the most constrained target. It uses the xenial GCC 5 runtime,
GCC 10 C++ headers for C++20 library declarations, and wrapper headers for
`<thread>` and `<future>` so thread construction uses the GCC 5 `_Impl_base`
ABI. Exceptions are disabled to avoid depending on newer exception ABI symbols.

```bash
sudo env UBUNTU_CODENAME=xenial \
  bash build-support/linux-sysroot/build-linux-sysroot.sh \
  .dexkit-sysroot/ubuntu-16.04-x86_64

bash build-support/linux-sysroot/fetch-libstdcxx-headers.sh \
  .dexkit-sysroot/gcc10-headers

SYSROOT="$PWD/.dexkit-sysroot/ubuntu-16.04-x86_64"
GCC10_HEADERS="$PWD/.dexkit-sysroot/gcc10-headers/usr/include"
COMPAT_DIR="$PWD/.dexkit-sysroot/compat"
COMPAT_HEADER="$COMPAT_DIR/glibc-libstdcxx10-compat.h"
WRAPPER_DIR="$COMPAT_DIR/gcc5-thread-wrapper"

mkdir -p "$WRAPPER_DIR"
cp build-support/linux-sysroot/glibc-libstdcxx10-compat.h "$COMPAT_HEADER"
sed "s|@TARGET_SYSROOT@|$SYSROOT|g" \
  build-support/linux-sysroot/gcc5-thread-wrapper/thread.in \
  > "$WRAPPER_DIR/thread"
sed "s|@TARGET_SYSROOT@|$SYSROOT|g" \
  build-support/linux-sysroot/gcc5-thread-wrapper/future.in \
  > "$WRAPPER_DIR/future"

export CC="clang --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export CXX="clang++ --sysroot=$SYSROOT --gcc-toolchain=$SYSROOT/usr"
export AR=llvm-ar
export RANLIB=llvm-ranlib
export LD=ld.lld
export CFLAGS=
export CXXFLAGS="-fno-exceptions -nostdinc++ -isystem $WRAPPER_DIR -isystem $GCC10_HEADERS/c++/10 -isystem $GCC10_HEADERS/x86_64-linux-gnu/c++/10 -include $COMPAT_HEADER"
export LDFLAGS="-Wl,--no-as-needed -lpthread"

./gradlew :dexkit:cmakeBuild --console=plain
```

Compared with 18.04, the 16.04 target additionally needs the GCC 5
`<thread>`/`<future>` wrappers and `-fno-exceptions`. These are only for the
GCC 5 libstdc++ runtime; they can be removed if the minimum target is raised to
18.04 or newer.
