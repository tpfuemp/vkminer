/*
 * Copyright 2012-2014 pooler
 * Copyright 2016-2025 Jay D Dee
 * Copyright 2026 vkminer contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * Derived from cpuminer-opt's compat.h. The MSVC section is gone -- the
 * Windows build here is mingw-w64, cross-compiled -- and so is the thread
 * priority shim, which existed for a --cpu-priority option this project
 * does not have.
 */

#ifndef VKMINER_COMPAT_H__
#define VKMINER_COMPAT_H__

#ifdef WIN32

#include <windows.h>
#include <time.h>

#ifndef localtime_r
#define localtime_r(src, dst) localtime_s(dst, src)
#endif

#define sleep(secs) Sleep((secs) * 1000)

#endif /* WIN32 */

#define _ALIGN(x) __attribute__ ((aligned(x)))

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#ifndef WIN32
#include <limits.h>
#define MAX_PATH PATH_MAX
#endif

#endif /* VKMINER_COMPAT_H__ */
