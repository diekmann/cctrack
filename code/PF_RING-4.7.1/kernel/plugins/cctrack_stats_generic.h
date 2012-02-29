/*
 * cctrack_stats_generic.h
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_STATS_GENERIC_H_
#define CCTRACK_STATS_GENERIC_H_

#include <linux/spinlock.h>

#include "cctrack.h"
#include "cctrack_controller.h"


/*
 * Stats about network, load. Collected per incoming packet (discarded or not).
 * designed for long time stats.
 * Stats output on per second basis
 */


//enough for 9 hours
#define CCTRACK_STATS_GENERIC_MAX 32768

//must be power of two, increase to reduce chance of int overflow
#define __CCTRACK_STATS_GENERIC_SL_FIELD 1048576



int init_cctrack_stats_generic(void);
void noinline exit_cctrack_stats_generic(void);


void cctrack_stats_generic_add_every_pkt(struct timeval *ts);

void cctrack_stats_generic_add_sampled_pkt(struct timeval *ts,
		uint32_t sampling_limit);

#endif /* CCTRACK_STATS_GENERIC_H_ */
