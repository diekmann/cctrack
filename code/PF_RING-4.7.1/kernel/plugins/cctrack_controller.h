/*
 * cctrack_controller.h
 *
 * Copyright (c) 2012, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_CONTROLLER_H_
#define CCTRACK_CONTROLLER_H_

#include <linux/types.h>
#include <linux/time.h>
#include <linux/spinlock.h>

#include "cctrack.h"
#include "cctrack_controller_perring.h"
#include "cctrack_ring_local_storage.h"


/* cctrack_controller_new_packet fills this structure for each packet */
struct cctrack_pid_controller{
	s32 proportional;

	/*
	 * the accumulated error since beginning
	 * @see struct cctrack_pid_controller_data
	 *
	 * time unit: seconds
	 */
	s32 integral;

	/*
	 * (deviation(time(i))-deviation(time(i-1))) / (time(i)-time(i-1))
	 *
	 * time unit: seconds
	 */
	s32 derivate;

};

/* params configured at module loadtime to scale the cctrack_pid_controller
 * and calculate the result.
 *
 * result = (proportional * K_P_dividend)/K_P_divisor +
 * 			(integral * K_I_dividend)/K_I_divisor +
 * 			(derivate * K_D_dividend)/K_D_divisor +
 *
 * The X_divisor_extra fields allow that the divisor is built with an external
 * extra variable.
 * If X_dixisor_extra == 1  =>  divisor = X_divisor * extra
 * If X_dixisor_extra == 0  =>  divisor = X_divisor
 *
 * For module initialization, a negative divisor value means that divisor_extra
 * must be set to 1 and the divisor changed to positive afterwards. During
 * operation, divisor is defined to be always positive.
 */
struct cctrack_pid_controller_params{
	s32 K_P_dividend;
	s32 K_P_divisor;
	/* extra: ring_buffer_size - (ring_buffer_size/buffer_target_fill_level) */
	s32 K_P_divisor_extra; // Bool

	s32 K_I_dividend;
	s32 K_I_divisor;

	s32 K_D_dividend;
	s32 K_D_divisor;
	/* extra: ring_buffer_size */
	s32 K_D_divisor_extra; // Bool
};




void cctrack_controller_init(void);
void cctrack_controller_exit(void);



void cctrack_controller_new_packet(struct cctrack_per_ring_data *this_ring_data,
		struct timeval now, int deviation,
		struct cctrack_pid_controller *pid);

/* get divisor of struct cctrack_pid_controller_params including extra and
 * check for constraints. */
s32 get_pid_divisor_P(struct cctrack_pid_controller_params *, s32 extra);
s32 get_pid_divisor_I(struct cctrack_pid_controller_params *);
s32 get_pid_divisor_D(struct cctrack_pid_controller_params *, s32 extra);

#endif /* CCTRACK_CONTROLLER_H_ */
