# Copyright (c) 2015 MADMAN Team
# APP_PLATFORM since android-9 support x86 (all32)
# APP_PLATFORM since android-21 support 64bit (all32 and all64)
APP_PLATFORM := android-9
NDK_TOOLCHAIN_VERSION=4.9
APP_PIE := false
APP_ABI := armeabi armeabi-v7a
APP_STL := gnustl_static

SECURE_LIBS := securejni
OPENSSL_LIBS:= libssl libcrypto


APP_MODULES := \
    $(SECURE_LIBS) \
    $(OPENSSL_LIBS)