/*
 * cctrack_stats_generic.c
 *
 * Statistics about the sampling limit and received packets.
 * One new entry per second.
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */


#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>

#include "cctrack_stats_generic.h"
#include "cctrack_util.h"
#include "cctrack.h"

#define CCTRACK_PROC_NAME "cctrack_stats_generic"


/* compile time check if power of two */
ct_assert(__CCTRACK_STATS_GENERIC_SL_FIELD &&
		!( (__CCTRACK_STATS_GENERIC_SL_FIELD-1)
				& __CCTRACK_STATS_GENERIC_SL_FIELD ));



/*** start flow statistics ***/

static atomic_t flowStats_num_seen; // number of seen flows
static atomic_t flowStats_num_stop_1; // number of flows stopen with sampling limit below X_1
static atomic_t flowStats_num_stop_2; //
static atomic_t flowStats_num_stop_3; //
static atomic_t flowStats_num_stop_4; // 
static atomic_t flowStats_num_stop_5; // 
static atomic_t flowStats_num_stop_6; // 

static void cctrack_stats_generic_flowStats_init(void) {
	atomic_set(&flowStats_num_seen, 0);
	atomic_set(&flowStats_num_stop_1, 0);
	atomic_set(&flowStats_num_stop_2, 0);
	atomic_set(&flowStats_num_stop_3, 0);
	atomic_set(&flowStats_num_stop_4, 0);
	atomic_set(&flowStats_num_stop_5, 0);
	atomic_set(&flowStats_num_stop_6, 0);
}

void cctrack_stats_generic_flowStats_new_flow(void) {
	atomic_inc(&flowStats_num_seen); //TODO check overflow
}

void cctrack_stats_generic_flowStats_flow_stop_duetosamplinglimit(uint32_t sampling_limit) {
	if (sampling_limit <= 65){
		atomic_inc(&flowStats_num_stop_1);
	}else if (sampling_limit <= 512){
		atomic_inc(&flowStats_num_stop_2);
	}else if (sampling_limit <= 1024){
		atomic_inc(&flowStats_num_stop_3);
	}else if (sampling_limit <= 10000){
		atomic_inc(&flowStats_num_stop_4);
	}else if (sampling_limit <= 100000){
		atomic_inc(&flowStats_num_stop_5);
	}else if (sampling_limit <= 1000000){
		atomic_inc(&flowStats_num_stop_6);
	} 
}

/*** end flow statistics ***/

/* ****************  forward declarations  ******************** */
static int cctrack_open(struct inode *inode, struct file *file);

extern unsigned int warn_min_sample_rate;


struct cctrack_stats_generic {
	/* 0 = everything okay
	 * 1 = general error
	 * 2 = overflow, not all stats could be saved in this struct */
	int status;

	/*
	 * The name RWLOCK is confusing: An arbitrary number of parallel threads
	 * can add stats with only holding the read lock! That's what atomics are
	 * for.
	 *
	 * The write lock is necessary when switching to a new time period (sec)
	 */
	rwlock_t lock;

	/* stats[0] to stats[pos - 1] contains valid collected data
	 * stats[pos] is the position stats are currently collected */
	unsigned int pos;

	struct {
		__kernel_time_t ts;     /* time stamp seconds*/


		atomic_t num_pkts;		/* packets seen in this period */

		/* packets tried to be sampled, includes lost packets */
		atomic_t num_pkts_sampled;

		/* sampling limit in this time period. Do not touch
		 * until time period is over */
		uint32_t sampling_limit_old;

		/* Number of packets below warn_min_sample_rate	 */
		atomic_t num_pkts_below_limit;

		/*
		 * 0 => all okay
		 * 1 => min sampling limit undercut
		 */
		int flags;
	}stats[CCTRACK_STATS_GENERIC_MAX];

	/* the sampling limit
	 * There are several sampling limts to calculate the average sampling
	 * limit:
	 * Average sampling limit: sum of sampling limits divided by
	 * num_pkts_sampled
	 * The several sampling limits are to prevent overflows:
	 * 	One adds the current sampling limit to an randomly chosen
	 * 	position in the array.
	 * */
	atomic_t sampling_limit[__CCTRACK_STATS_GENERIC_SL_FIELD];
};


/* the sampling_limit accumulator field is larger than 1 MByte */
ct_assert(sizeof(((struct cctrack_stats_generic *)0)->sampling_limit)
		>= 1 * 1024 * 1024);

/* the sampling_limit accumulator field i less than 4 MByte */
ct_assert(sizeof(((struct cctrack_stats_generic *)0)->sampling_limit)
		<= 4 * 1024 * 1024);

/* ****************  global vars  ******************** */
static struct cctrack_stats_generic *cctrack_stats_generic = NULL;


//mutex for reading file from userspace
static DEFINE_MUTEX(cctrack_stats_dynamic_proc_mutex);

static const struct file_operations proc_cctrack_stats_operations = {
		.open           = cctrack_open,
		.read           = seq_read,
		.llseek         = seq_lseek,
		.release        = seq_release,
};


/* ****************  function for /proc interface  ******************** */
/* @see /Documentation/filesystems/seq_file.txt */


/* The iterator is a simple index into the stats array */
static void *cctrack_seq_start(struct seq_file *s, loff_t *pos)
{
	loff_t *spos;
	//printk("cctrack_seq_start %lld \n", *pos);

	mutex_lock(&cctrack_stats_dynamic_proc_mutex);

	spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
	cctrack_assert(spos != NULL);
	if (! spos){
		return NULL;
	}

	if(*pos >= CCTRACK_STATS_GENERIC_MAX){
		return NULL;
	}




	if(*pos >= cctrack_stats_generic->pos){
		//no more old data left to read
		return NULL;
	}

	*spos = *pos;

	return spos;
}

static void *cctrack_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	loff_t *spos = (loff_t *) v;
	//printk("cctrack_seq_next %lld %lld\n", *spos, *pos);
	*pos = ++(*spos);


	if(*pos >= CCTRACK_STATS_GENERIC_MAX){
		return NULL;
	}

	//no lock as read only copy
	if(*pos >= cctrack_stats_generic->pos){
		spos = NULL;
	}

	return spos;
}


static void cctrack_seq_stop(struct seq_file *s, void *v)
{
	loff_t spos;

	//printk("cctrack_seq_stop %p\n", v);

	if(v != NULL){
		spos = *((loff_t *) v);

		cctrack_assert((s64)cctrack_stats_generic->pos >= (s64)spos);


		if(spos == cctrack_stats_generic->pos){
			//all stats were read
			//printk("all data read\n");
		}
	}

	if(v != NULL){
		kfree(v);
	}

	mutex_unlock(&cctrack_stats_dynamic_proc_mutex);
}


/* will be called when reading the proc file */
static int cctrack_seq_show(struct seq_file *s, void *v)
{
	unsigned int i;
	loff_t pos = *((loff_t *)v);
	u64 avg_sampling = 0;
	int num_pkts_sampled, num_pkts, num_pkts_below_limit;

	cctrack_assert(s->private == NULL);
	cctrack_assert(v != NULL);

	//printk("cctrack_seq_show %lld \n", pos);

	cctrack_assert(pos < CCTRACK_STATS_GENERIC_MAX);

	cctrack_assert(pos < cctrack_stats_generic->pos);

	i = pos;
	cctrack_assert(i == pos);


	if(i==0){
	
		/*** start flow statistics ***/
		seq_printf(s, "# cctrack flow statistics\n");
		seq_printf(s, "%d %d %d %d %d %d %d\n",
			atomic_read(&flowStats_num_seen),
			atomic_read(&flowStats_num_stop_1),
			atomic_read(&flowStats_num_stop_2),
			atomic_read(&flowStats_num_stop_3),
			atomic_read(&flowStats_num_stop_4),
			atomic_read(&flowStats_num_stop_5),
			atomic_read(&flowStats_num_stop_6)
			);
		seq_printf(s, "# happy newline\n");
		/*** end flow statistics ***/


		seq_printf(s, "# cctrack generic stats\n");
		if(cctrack_stats_generic->status == 0){
			seq_printf(s, "# no errors logged\n");
		}else if(cctrack_stats_generic->status == 2){
			seq_printf(s, "# error: stats buffer went full, only the first %d "
					"packets were logged\n", CCTRACK_STATS_GENERIC_MAX);
		}else{
			seq_printf(s, "# ERROR\nstatus was %d\n",
					cctrack_stats_generic->status);
		}
		seq_printf(s, "# timestamp -- Tot Num Pkts -- Pkts Sampled "
				"-- Average Sampling Limit [warnings]\n");
	}

	num_pkts_sampled =
			atomic_read(&cctrack_stats_generic->stats[i].num_pkts_sampled);
	num_pkts = atomic_read(&cctrack_stats_generic->stats[i].num_pkts);
	num_pkts_below_limit =
			atomic_read(&cctrack_stats_generic->stats[i].num_pkts_below_limit);

	avg_sampling = cctrack_stats_generic->stats[i].sampling_limit_old;

	cctrack_assert(num_pkts_sampled >= 0);
	cctrack_assert(num_pkts >= 0);
	cctrack_assert(num_pkts_below_limit >= 0);

	/* Packets for the generic stats can be inserted without holding a write
	 * lock.
	 * The following tolerable race condition exists:
	 * The num_packets is increased, a new second-slot for inserting data is
	 * opened and the num_pkts_sampled is then increased in this new slot.
	 * Thus num_pkts >= num_pkts_sampled must not hold!
	 * However, nothing is lost here, the packets are just in the wrong second.
	 * The average stats are consistent and that is the interesting thing.
	 * More precise stats would require more locking which is not worth
	 * the cpu time. The statistical average when looking at a few seconds
	 * of stats is totally consistent.
	 * 	Thats what the 32 is for, compensate this race condition and only
	 * 	trigger the assertion if violation is large.*/
	cctrack_assert(num_pkts + 32 >= num_pkts_sampled);
	cctrack_assert(num_pkts + 32 >= num_pkts_below_limit);

	if(num_pkts_sampled == 0){
		// nothing but remember to handle division by zero if you want some
		// percentage stats in future, aye?
	}else{
		//nothing
	}

	
	cctrack_assert((cctrack_stats_generic->stats[i].flags == 1) ?
					num_pkts_below_limit > 0 : num_pkts_below_limit == 0);
	seq_printf(s, "%lu %d %d %llu %d\n",
			cctrack_stats_generic->stats[i].ts,
			num_pkts,
			num_pkts_sampled,
			avg_sampling,
			num_pkts_below_limit
			);


	return 0;
}



static const struct seq_operations cctrack_seq_ops = {
	.start = cctrack_seq_start,
	.next  = cctrack_seq_next,
	.stop  = cctrack_seq_stop,
	.show  = cctrack_seq_show
};

/* The /proc open */
static int cctrack_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cctrack_seq_ops);
};


/* Force a compilation error if a constant expression is not a power of 2 */
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)                  \
         BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))

/* ****************  init & cleanup functions  ******************** */

/* @returns 0 on success */
int init_cctrack_stats_generic(void){
	struct proc_dir_entry *proc_file;
	struct timeval now;
	int i,j;


	BUILD_BUG_ON_NOT_POWER_OF_2(__CCTRACK_STATS_GENERIC_SL_FIELD);
	
	/*** start flow statistics ***/
	cctrack_stats_generic_flowStats_init();
	/*** end flow statistics ***/

	cctrack_stats_generic = vmalloc(sizeof(struct cctrack_stats_generic));
	if(cctrack_stats_generic == NULL){
		printk("could not allocate memory for cctrack_stats_generic\n");
		return -1;
	}

	rwlock_init(&cctrack_stats_generic->lock);
	cctrack_stats_generic->status = 0;
	cctrack_stats_generic->pos = 0;

	write_lock_bh(&cctrack_stats_generic->lock);
	for(i=0; i<CCTRACK_STATS_GENERIC_MAX; ++i){
		cctrack_stats_generic->stats[i].ts = 0;
		cctrack_stats_generic->stats[i].sampling_limit_old = 0;
		atomic_set(&cctrack_stats_generic->stats[i].num_pkts, 0);
		atomic_set(&cctrack_stats_generic->stats[i].num_pkts_sampled, 0);
		atomic_set(&cctrack_stats_generic->stats[i].num_pkts_below_limit, 0);
		cctrack_stats_generic->stats[i].flags = 0;
	}
	for(j=0; j< __CCTRACK_STATS_GENERIC_SL_FIELD; ++j){
		atomic_set(&cctrack_stats_generic->sampling_limit[j], 0);
	}
	write_unlock_bh(&cctrack_stats_generic->lock);

	proc_file = proc_create(CCTRACK_PROC_NAME, 0, NULL,
			&proc_cctrack_stats_operations);

	if (proc_file == NULL) {
		vfree(cctrack_stats_generic);
		printk("Error: Could not initialize /proc/%s\n", CCTRACK_PROC_NAME);
		return -1;
	}

	cctrack_assert(cctrack_stats_generic->pos == 0);

	do_gettimeofday(&now);
	cctrack_stats_generic->stats[0].ts = now.tv_sec;

	printk("Stats available at /proc/%s\n", CCTRACK_PROC_NAME);

	return 0;
}

void noinline exit_cctrack_stats_generic(void){
	remove_proc_entry(CCTRACK_PROC_NAME, NULL);

	write_lock_bh(&cctrack_stats_generic->lock);
	cctrack_stats_generic->pos = 0;
	write_unlock_bh(&cctrack_stats_generic->lock);


	if(cctrack_stats_generic != NULL){
		vfree(cctrack_stats_generic);
	}

}


/* ****************  functions  ******************** */

//debug to trace whether the sampling limit field is evenly distributed
// #define CCTRACK_OVEFLOW_PROFILING

/* must be called from softirq context */
void cctrack_stats_generic_add_every_pkt(struct timeval *ts)
{

	typeof(cctrack_stats_generic->pos) pos; //local copy
	bool need_update_and_clean;

	read_lock(&cctrack_stats_generic->lock);


	if(cctrack_stats_generic->pos >= CCTRACK_STATS_GENERIC_MAX){
		if(cctrack_stats_generic->status == 0){ //print once
			printk("cctrack_stats_generic overflow! no more data can be "
					"recorded!\n");
		}

		cctrack_stats_generic->status = 2; /* overflow */
		read_unlock(&cctrack_stats_generic->lock);
		return;
	}

	pos = cctrack_stats_generic->pos;
	cctrack_assert(pos >= 0 && pos <= CCTRACK_STATS_GENERIC_MAX);

	atomic_inc(&cctrack_stats_generic->stats[pos].num_pkts);

	need_update_and_clean = ts->tv_sec > cctrack_stats_generic->stats[pos].ts;
	read_unlock(&cctrack_stats_generic->lock);


	if(need_update_and_clean){
		//increment stats slot as a new second starts
		int j, k;
		s64 sampling_tmp;
		s64 sampling_tmp_acc = 0; /* accumulator to reduce rounding errors */
		int num_pkts_sampled;
#ifdef CCTRACK_OVEFLOW_PROFILING
		int fields_zero = 0;
#endif

		write_lock(&cctrack_stats_generic->lock);
		//now we have exclusive control of the stats
		// we are responsible for aggregating results and setting up new slot

		if(pos != cctrack_stats_generic->pos){
			//another thread already prepared the new slot
			cctrack_assert(pos < cctrack_stats_generic->pos);
			write_unlock(&cctrack_stats_generic->lock);
			return;
		}


		num_pkts_sampled = atomic_read(
				&cctrack_stats_generic->stats[pos].num_pkts_sampled);
		cctrack_assert(num_pkts_sampled>=0);

#ifdef CCTRACK_OVEFLOW_PROFILING
		printk("updating %d -> %d (pos:%d)\n", cctrack_stats_generic->pos,
				cctrack_stats_generic->pos+1, pos);
#endif


		//calculate avg sampling limit for present time slot
		cctrack_assert(
				cctrack_stats_generic->stats[pos].sampling_limit_old == 0);
		cctrack_stats_generic->stats[pos].sampling_limit_old = 0;
		for(k=0; k < __CCTRACK_STATS_GENERIC_SL_FIELD; ++k)
		{
			sampling_tmp = atomic_read(
					&cctrack_stats_generic->sampling_limit[k]);

			cctrack_assert(sampling_tmp < INT_MAX); //possible overflow
			cctrack_assert(sampling_tmp >= 0); //possible overflow

#ifdef CCTRACK_OVEFLOW_PROFILING
			if(sampling_tmp == 0){ ++fields_zero; }
#endif


			if(num_pkts_sampled == 0){
				// nothing, avoid division by zero
			}else{
				cctrack_stats_generic->stats[pos].sampling_limit_old
								+= sampling_tmp/num_pkts_sampled;
				sampling_tmp_acc += sampling_tmp % ((s64)num_pkts_sampled);
			}

		}
		if(num_pkts_sampled == 0){
			// nothing, avoid division by zero
		}else{
			cctrack_stats_generic->stats[pos].sampling_limit_old
							+= sampling_tmp_acc/num_pkts_sampled;
		}

		//prepare new slot
		pos = ++cctrack_stats_generic->pos;

		cctrack_stats_generic->stats[pos].ts = ts->tv_sec;
		atomic_set(&cctrack_stats_generic->stats[pos].num_pkts, 0);
		atomic_set(&cctrack_stats_generic->stats[pos].num_pkts_sampled, 0);

		//reset field
		for(j=0; j< __CCTRACK_STATS_GENERIC_SL_FIELD; j++){
			atomic_set(&cctrack_stats_generic->sampling_limit[j], 0);
		}

#ifdef CCTRACK_OVEFLOW_PROFILING
		printk("updating %d -> %d unused fields: %d\n", cctrack_stats_generic->pos,
				cctrack_stats_generic->pos+1, fields_zero);
#endif

		write_unlock(&cctrack_stats_generic->lock);
	} /* endif need_update_and_clean */
}



void cctrack_stats_generic_add_sampled_pkt(struct timeval *ts,
		uint32_t sampling_limit)
{

	typeof(cctrack_stats_generic->pos) pos; //local copy

	/*
	 * sl_pos: random position into the cctrack_stats_generic->sampling_limit
	 * field. The position must not be random but should be evenly distributed.
	 * First idea is to use the lower bits of ts->tv_usec but
	 * if the NIC doesn't support it, they can be all zero.
	 */
	int sl_pos = 0;

	read_lock(&cctrack_stats_generic->lock);


	if(cctrack_stats_generic->pos >= CCTRACK_STATS_GENERIC_MAX){
		if(cctrack_stats_generic->status == 0){ //print once
			printk("cctrack_stats_generic overflow! no more data can be "
					"recorded!\n");
		}

		cctrack_stats_generic->status = 2; /* overflow */
		read_unlock(&cctrack_stats_generic->lock);
		return;
	}
	pos = cctrack_stats_generic->pos;

	sl_pos = (int)ts->tv_usec; // initial entropy, may be zero

	// more entropy
	sl_pos += atomic_read(&cctrack_stats_generic->stats[pos].num_pkts);

	//only look at last bits
	sl_pos = (sl_pos & (__CCTRACK_STATS_GENERIC_SL_FIELD-1));
	cctrack_assert(sl_pos >= 0 && sl_pos < __CCTRACK_STATS_GENERIC_SL_FIELD);

	atomic_inc(&cctrack_stats_generic->stats[pos].num_pkts_sampled);
	atomic_add(sampling_limit,
			&cctrack_stats_generic->sampling_limit[sl_pos]);
	//TODO maybe check for overflows, but those are rare


	if(sampling_limit < warn_min_sample_rate){
		cctrack_printk_once("cctrack: sampling limit below threshold! "
				"is: %d threshold: %d\n", sampling_limit, warn_min_sample_rate);

		cctrack_stats_generic->stats[pos].flags |= 1;
		atomic_inc(&cctrack_stats_generic->stats[pos].num_pkts_below_limit);
	}


	read_unlock(&cctrack_stats_generic->lock);
}

