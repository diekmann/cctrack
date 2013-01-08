/*
 * cctrack_ring_local_storage.c
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#include <asm/system.h> /* smp_mb */
#include <linux/slab.h> /* kmalloc */
#include <asm/atomic.h>

#include "cctrack.h"
#include "cctrack_util.h"
#include "cctrack_ring_local_storage.h"


/* a global array of this type exists to link a ring to its
 * cctrack_per_ring_data.
 */
struct cctrack_ring_local_storage_array {

	struct {
		/*
		 * status of this entry
		 * 0: this entry is free an can be used
		 * 1: this entry is invalid, e.g. during initialization
		 * >=2: this entry contains valid data
		 */
		atomic_t status;

		/*
		 * the key to link this entry to a ring
		 */
		u_short ring_pid;
		u_int32_t ring_id;

		/*
		 * the ring local data
		 * use (struct pf_ring_socket)->ring_index_lock to synchronize access
		 * to this entry.
		 */
		struct cctrack_per_ring_data *data;

	} per_ring[PER_RING_LOCAL_DATA_MAX];
};


static struct cctrack_ring_local_storage_array cctrack_per_ring;



void cctrack_ring_local_storage_init(void)
{
	int i = 0;

	for(i=0; i<PER_RING_LOCAL_DATA_MAX; ++i){
		atomic_set(&cctrack_per_ring.per_ring[i].status, 0);
		cctrack_per_ring.per_ring[i].data =
				kmalloc(sizeof(struct cctrack_per_ring_data), GFP_KERNEL);
		cctrack_assert(cctrack_per_ring.per_ring[i].data != NULL);

		cctrack_per_ring.per_ring[i].ring_id = 0;
		cctrack_per_ring.per_ring[i].ring_pid = 0;
	}

}

void noinline cctrack_ring_local_storage_exit(void){
	int i = 0;

	for(i=0; i<PER_RING_LOCAL_DATA_MAX; ++i){
		cctrack_assert(cctrack_per_ring.per_ring[i].data != NULL);
		kfree(cctrack_per_ring.per_ring[i].data);
	}
}



/* @return 0 on error, 1 on success,  */
int cctrack_init_new_ring_storage(u_short ring_pid, u_int32_t ring_id)
{
	int i = 0;

	int cond;

	for(i=0; i<PER_RING_LOCAL_DATA_MAX; ++i){
		cond = atomic_add_return(1, &cctrack_per_ring.per_ring[i].status);
		if(cond >= 2){
			// this position is already taken
			atomic_dec(&cctrack_per_ring.per_ring[i].status);

			if(cctrack_per_ring.per_ring[i].ring_id == ring_id &&
					cctrack_per_ring.per_ring[i].ring_pid == ring_pid){
				//the requested bucket has already been initialized
				return 1;
			}

		}else if(cond == 1){
			//successfully occupied empty array position

			/*
			 * here is a race condition:
			 * If someone calls cctrack_init_new_ring_storage now,
			 * this position will be set to two for a very short period
			 * and somebody might read this entry as it is marked
			 * as valid position.
			 *
			 * make sure there are no parallel calls to this function!
			 */
			cctrack_per_ring.per_ring[i].ring_id = ring_id;

			INIT_struct_cctrack_per_ring_data(cctrack_per_ring.per_ring[i].data);


			// now it can be recognized valid
			cctrack_per_ring.per_ring[i].ring_pid = ring_pid;
			mb();
			atomic_inc(&cctrack_per_ring.per_ring[i].status); // valid

			printk("registered local storage for ring %d\n", i);
			return 1;
		}else{
			/* this case is impossible! */
			cctrack_assert(0);
		}
	}
	//printk("cctrack_per_ring full\n");
	return 0;

}

//#define HACK_ADDITONAL_INEFFICIENT_LOCKING_TO_PREVENT_INITIALIZATION_RACE_CONDITION
#ifdef HACK_ADDITONAL_INEFFICIENT_LOCKING_TO_PREVENT_INITIALIZATION_RACE_CONDITION
static DEFINE_SPINLOCK(ugly_cctrack_get_ring_storage_lock);
#endif

struct cctrack_per_ring_data * cctrack_get_ring_storage(u_short ring_pid,
		u_int32_t ring_id)
{
	int i = 0;
	int bucket_status;

#ifdef HACK_ADDITONAL_INEFFICIENT_LOCKING_TO_PREVENT_INITIALIZATION_RACE_CONDITION
    struct cctrack_per_ring_data *retval = NULL;
    spin_lock(&ugly_cctrack_get_ring_storage_lock);
#endif	

	for(i=0; i<PER_RING_LOCAL_DATA_MAX; ++i){
		bucket_status = atomic_read(&cctrack_per_ring.per_ring[i].status);
		if(bucket_status == 1){
			// someone is doing initialization in this data structure
			// wait until fully initialized as this initialization
			// might be the bucket we are looking for

			i=0; //busy waiting!
			continue;
		}
		if(bucket_status >= 2){
			if(cctrack_per_ring.per_ring[i].ring_pid == ring_pid &&
					cctrack_per_ring.per_ring[i].ring_id == ring_id){
#ifdef HACK_ADDITONAL_INEFFICIENT_LOCKING_TO_PREVENT_INITIALIZATION_RACE_CONDITION
				retval = cctrack_per_ring.per_ring[i].data;
				break;
#else
				return cctrack_per_ring.per_ring[i].data;
#endif
			}
		}
	}
#ifdef HACK_ADDITONAL_INEFFICIENT_LOCKING_TO_PREVENT_INITIALIZATION_RACE_CONDITION
    spin_unlock(&ugly_cctrack_get_ring_storage_lock);
    return retval;
#else	
	return NULL;
#endif
}


