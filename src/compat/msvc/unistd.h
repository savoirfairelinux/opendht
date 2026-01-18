// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#ifndef __STRICT_ANSI__

#include <stdlib.h>
#include <process.h>
#include <direct.h>
#include <fcntl.h>
#include <synchapi.h>

#define R_OK 4
#define W_OK 2
#define F_OK 0

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#define srandom srand
#define random  rand

#define inline __inline
typedef int mode_t;
#include <BaseTsd.h>

#endif
