LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := agent
LOCAL_SRC_FILES := agent.c
LOCAL_LDLIBS  := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
