// downloaded from http://androidxref.com/9.0.0_r3/xref/bionic/linker/linker_relocs.h

/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include <elf.h>

#define R_GENERIC_NONE 0 // R_*_NONE is always 0

#if defined (__aarch64__)

#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE

#elif defined (__arm__)

#define R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT
#define R_GENERIC_RELATIVE  R_ARM_RELATIVE
#define R_GENERIC_IRELATIVE R_ARM_IRELATIVE

#elif defined (__i386__)

#define R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define R_GENERIC_RELATIVE  R_386_RELATIVE
#define R_GENERIC_IRELATIVE R_386_IRELATIVE

#elif defined (__x86_64__)

#define R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_X86_64_RELATIVE
#define R_GENERIC_IRELATIVE R_X86_64_IRELATIVE

#endif
