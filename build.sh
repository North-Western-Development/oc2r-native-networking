#!/bin/sh -e
# shellcheck disable=2086

[ -z "$CFLAGS" ] && CFLAGS='-Os -Wall -Wextra -pedantic'

[ -z "$CLANG" ] && CLANG=clang
[ -z "$STRIP" ] && STRIP=llvm-strip

# build for mac

for dep in wget $CLANG $STRIP; do
    if ! command -v "$dep" > /dev/null; then
        printf "Error: Missing dependency: %s\n" "$dep"
        exit 1
    fi
done

if ! [ -d macsdk ]; then
    wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX11.0.sdk.tar.xz -O- | tar -xJ
    mv MacOS* macsdk
fi

mkdir -p build

$CLANG $CFLAGS -std=c99 -Ijni-headers -fuse-ld=lld oc2rnet.c -bundle -target x86_64-apple-macos10.8 -isysroot macsdk -o build/liboc2rnet-x86_64.dylib
$CLANG $CFLAGS -std=c99 -Ijni-headers -fuse-ld=lld oc2rnet.c -bundle -target arm64-apple-macos11.0 -isysroot macsdk -o build/liboc2rnet-arm64.dylib

# build for android

if ! [ -d ndk ]; then
    ndkver=29
    wget "https://dl.google.com/android/repository/android-ndk-r$ndkver-linux.zip" -O ndk.zip
    unzip ndk.zip
    rm -f ndk.zip
    mv "android-ndk-r$ndkver" ndk
fi
ndkbin='ndk/toolchains/llvm/prebuilt/linux-x86_64/bin'
"$ndkbin/aarch64-linux-android21-clang" $CFLAGS -std=c99 oc2rnet.c -shared -o build/liboc2rnet-android-arm64.so
"$ndkbin/x86_64-linux-android21-clang" $CFLAGS -std=c99 oc2rnet.c -shared -o build/liboc2rnet-android-x86_64.so

# build for other platforms

if ! [ -d zig ]; then
    wget https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz -O- | tar -xJ
    mv zig-* zig
fi

./zig/zig cc $CFLAGS -std=c99 -D_DEFAULT_SOURCE -Ijni-headers oc2rnet.c -shared -target x86_64-linux-gnu -o build/liboc2rnet-linux-x86_64.so
./zig/zig cc $CFLAGS -std=c99 -D_DEFAULT_SOURCE -Ijni-headers oc2rnet.c -shared -target aarch64-linux-gnu -o build/liboc2rnet-linux-arm64.so
./zig/zig cc $CFLAGS -std=c99 -Ijni-headers oc2rnet.c -shared -target x86_64-windows-gnu -o build/oc2rnet-x86_64.dll -licmp
./zig/zig cc $CFLAGS -std=c99 -Ijni-headers oc2rnet.c -shared -target aarch64-windows-gnu -o build/oc2rnet-arm64.dll -licmp

rm build/*.lib

$STRIP ./build/*
