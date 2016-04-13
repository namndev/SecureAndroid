# Copyright (c) 2016 MADMAN

LOCAL_PATH := $(call my-dir)

# prepare libssl
include $(CLEAR_VARS)
LOCAL_MODULE    := libssl
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libssl.a
include $(PREBUILT_STATIC_LIBRARY)

# prepare libcrypto
include $(CLEAR_VARS)
LOCAL_MODULE    := libcrypto
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_STATIC_LIBRARIES := libssl \
                          libcrypto
LOCAL_MODULE := securejni

LOCAL_CPP_EXTENSION := .cxx

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/include

LOCAL_SRC_FILES := \
	SecureJni.cxx \
	ProcHmac.cxx \
	ProcCrypto.cxx

LOCAL_LDLIBS += -llog

include $(BUILD_SHARED_LIBRARY)
