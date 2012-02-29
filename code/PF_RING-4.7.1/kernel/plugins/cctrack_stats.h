/*
 * cctrack_stats.h
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_STATS_PID_H_
#define CCTRACK_STATS_PID_H_

#include <linux/spinlock.h>

#include "cctrack.h"
#include "cctrack_controller.h"

/*
 * Stats for the PID controller and sampling limit, for each packet which is
 * not discared by cctrack
 */

// moderate: #define CCTRACK_STATS_PID_MAX 32768

#define CCTRACK_STATS_PID_MAX 1048576 // about 45 MByte



int init_cctrack_stats_pid(void);
void exit_cctrack_stats_pid(void);


void cctrack_stats_pid_add(int buffer_target_deviation, struct timeval *ts,
		struct cctrack_pid_controller *pid, uint32_t sampling_limit,
		u_int32_t ring_id);

#endif /* CCTRACK_STATS_PID_H_ */
