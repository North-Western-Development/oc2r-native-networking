#!/bin/sh -e
# shellcheck disable=2086

[ -z "$CFLAGS" ] && CFLAGS='-Os -Wall -Wextra -pedantic'

[ -z "$CLANG" ] && CLANG=clang
[ -z "$STRIP" ] && STRIP=llvm-strip

# build for mac

for dep in wget $CLANG $STRIP; do
    if ! command -v "$dep" > /dev/null; then
        error "Missing dependency: $dep"
    fi
done

if ! [ -d macsdk-intel ]; then
    wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX10.8.sdk.tar.xz -O- | tar -xJ
    mv MacOS* macsdk-intel
fi

if ! [ -d macsdk-arm64 ]; then
    wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX11.0.sdk.tar.xz -O- | tar -xJ
    mv MacOS* macsdk-arm64
fi

$CLANG $CFLAGS -Ijni-headers -fuse-ld=lld oc2rnet.c -shared -target x86_64-apple-macos10.8 -isysroot macsdk-intel -o liboc2rnet-x86_64.dylib
$CLANG $CFLAGS -Ijni-headers -fuse-ld=lld oc2rnet.c -shared -target arm64-apple-macos11.0 -isysroot macsdk-arm64 -o liboc2rnet-arm64.dylib

$STRIP liboc2rnet-*

# build for other platforms

if ! [ -d zig ]; then
    wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz -O- | tar -xJ
    mv zig-* zig
fi

zig/zig cc $CFLAGS -Ijni-headers oc2rnet.c -static -shared -target x86_64-linux-musl -o liboc2rnet-linux-x86_64.so
zig/zig cc $CFLAGS -Ijni-headers oc2rnet.c -static -shared -target aarch64-linux-musl -o liboc2rnet-linux-arm64.so
zig/zig cc $CFLAGS -Ijni-headers oc2rnet.c -shared -target x86_64-windows-gnu -o oc2rnet-x86_64.dll -licmp
zig/zig cc $CFLAGS -Ijni-headers oc2rnet.c -shared -target aarch64-windows-gnu -o oc2rnet-arm64.dll -licmp

$STRIP ./*.so ./*.dylib
