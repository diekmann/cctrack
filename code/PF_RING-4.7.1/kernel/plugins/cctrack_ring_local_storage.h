/*
 * cctrack_ring_local_storage.h
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_RING_LOCAL_STORAGE_H_
#define CCTRACK_RING_LOCAL_STORAGE_H_

#include <linux/types.h>
#include "cctrack_controller_perring.h"

//not implemented!
// #define CCTRACK_RING_LOCAL_LOCKINGFREE

/* data structures for storing data only for a specific ring
 * SMP safe and locking free, fast */


/* data only valid for a specific ring.
 * pfr->ring_index_lock must be locked when using this data.
 * */
struct cctrack_per_ring_data {
	/* The ring's insert_off is not updated for each packet.
	 * We need to track the data which will be put in the buffer in future.
	 * This will be called insert_offset_tracing, when grepping the srccode */
#ifndef CCTRACK_RING_LOCAL_LOCKINGFREE
	uint32_t last_insert_off;
	uint32_t last_lost_pkt;
	uint32_t inserted_bytes_since_last_insert_off_update;
	/*
	 * Locking order:
	 * 1) the_ring->ring_index_lock
	 * 2) lock_insert_offset_tracing
	 * 2) vars.lock
	 */
	spinlock_t lock_insert_offset_tracing;
#else
	atomic_t last_insert_off;
	atomic_t last_lost_pkt;
	atomic_t inserted_bytes_since_last_insert_off_update;
#endif

	/* the important properties like the sampling limit */
	struct cctrack_properties vars;

	/* current pid state */
	struct cctrack_pid_controller_data pid_controller_data;
};


#define INIT_struct_cctrack_per_ring_data(d) \
	do{ \
		/* init insert_offset_tracing */ \
		d->last_insert_off = 0; \
		d->last_lost_pkt = 0;\
		d->inserted_bytes_since_last_insert_off_update = 0;\
		spin_lock_init(&d->lock_insert_offset_tracing); \
		/* set sampling options */ \
		rwlock_init(&d->vars.lock); \
		write_lock(&d->vars.lock); \
		d->vars.timeout = timeout; /* module param */ \
		d->vars.sampling_limit = sample_limit; /* module param */ \
		d->vars.sampling_limit_fut = sample_limit; /* module param */ \
		d->vars.inertia_pkt_cnt = 0; \
		write_unlock(&d->vars.lock); \
		/* init pid controller data */ \
		cctrack_controller_init_state(&d->pid_controller_data); \
	}while(0)


#define PER_RING_LOCAL_DATA_MAX 32



void cctrack_ring_local_storage_init(void);
void cctrack_ring_local_storage_exit(void);


int cctrack_init_new_ring_storage(u_short ring_pid, u_int32_t ring_id);


struct cctrack_per_ring_data *
	cctrack_get_ring_storage(u_short ring_pid, u_int32_t ring_id);


#endif /* CCTRACK_RING_LOCAL_STORAGE_H_ */
