/*
 * cctrack_util.c
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#include "cctrack_util.h"
#include <linux/types.h>
#include <linux/time.h>

// everything inline so far


#ifndef CONFIG_X86_64
#error "only X86_64 supported"
#endif

//basic assumptions about data types
//you get  "warning: division by zero" if assertion fails
ct_assert(sizeof(int) == sizeof(int32_t));
ct_assert(sizeof(long long) == sizeof(s64));
ct_assert(sizeof(int) == sizeof(s32));

//timestamp is a long
ct_assert(sizeof(((struct timeval *)0)->tv_sec) == sizeof(long));
// timestamp must be more than 32bit for stats being in USEC
ct_assert(sizeof(((struct timeval *)0)->tv_sec) > sizeof(s32));



