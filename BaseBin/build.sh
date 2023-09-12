#!/bin/sh

# build launchdhook

mkdir -p build

set -e

CFLAGS="-O2 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch arm64e -miphoneos-version-min=14.0 -fobjc-arc"

clang $CFLAGS launchdhook/main.m common/util.m common/macho.m common/common.c -o build/launchdhook.dylib -framework IOKit -shared -L. -lellekit -rpath @loader_path/ #-rpath /var/jb/Library/Frameworks

clang $CFLAGS systemhook/main.c common/common.c common/dl_util.m -o build/systemhook.dylib -shared

clang $CFLAGS forkfix/main.c forkfix/syscall.S -o build/forkfix.dylib -shared -L. -lellekit -rpath @loader_path/ #-rpath /var/jb/Library/Frameworks

ldid -S build/launchdhook.dylib

ldid -S build/systemhook.dylib

pushd rootlesshooks

make DEBUG=0

popd

cp rootlesshooks/.theos/obj/rootlesshooks.dylib build/

cp ldid/ldid build/

ldid -M -S build/ldid

cp opainject/opainject build/opainject

cp -r ellekit/CydiaSubstrate.framework build/

rm -rf "./basebin.tc"
trustcache create "./basebin.tc" "./build"
cp "./basebin.tc" "./build"

pushd build
tar -cf basebin.tar launchdhook.dylib opainject systemhook.dylib CydiaSubstrate.framework basebin.tc rootlesshooks.dylib ldid
popd

cp build/basebin.tar ../arm/iOS/Fugu14App/Fugu14App/