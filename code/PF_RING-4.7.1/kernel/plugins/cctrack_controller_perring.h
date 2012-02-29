/*
 * cctrack_controller_perring.h
 *
 * Auxiliary header file. Do nor use directly.
 *
 * Copyright (c) 2012, Cornelius Diekmann
 * All rights reserved.
 */

#if !(defined CCTRACK_CONTROLLER_H_ || defined CCTRACK_RING_LOCAL_STORAGE_H_)
#error "this file is internal, I hope you know what you're doing"
#endif

#ifndef CCTRACK_CONTROLLER_PERRING_H_
#define CCTRACK_CONTROLLER_PERRING_H_



/*
 * struct to collect the data for a pid controller
 * a instance is stored for each rin in the ring_local_storage.
 * For internal use only
 */
struct cctrack_pid_controller_data{
	/*
	 * sum from i=0 to ...: deviation(time(i))*(time(i)-time(i-1))
	 * time unit: seconds
	 */
	//invariant INT_MIN <= integral <= INT_MAX;
	s64 integral;

	/* deviation(time(i-1)) */
	s32 previous_deviation;

	/* previous_deviation = deviation(time(i-1)) */
	struct timeval previous_t;

	spinlock_t lock;
};



/* called when initializing ring_local_storage */
void cctrack_controller_init_state(struct cctrack_pid_controller_data*);


#endif /* CCTRACK_CONTROLLER_PERRING_H_ */
