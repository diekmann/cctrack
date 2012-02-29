/*
 * cctrack_stats.c
 *
 * Statistics for each packet.
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

#include "cctrack_stats.h"
#include "cctrack_util.h"
#include "cctrack.h"

#define CCTRACK_PROC_NAME "cctrack_stats_pid"

/* ****************  forward declarations  ******************** */
static int cctrack_open(struct inode *inode, struct file *file);

struct cctrack_stats_pid {
	/* 0 = everything okay
	 * 1 = general error
	 * 2 = overflow, not all stats could be saved in this struct
	 * atomic so function can return without lock on overflow*/
	atomic_t status;

	/* dyn_sampling_stats[0] to dyn_sampling_stats[dyn_sampling_stats_limit - 1]
	 * contains valid data */
	unsigned int dyn_sampling_stats_limit;

	/* Number of logged and printed packets. The packet number for packet i in
	 * dyn_sampling_stats is num_packets + i
	 * This number is maintained to discard the stats info after they are read
	 * via /proc */
	u64 num_packets;

	struct {
		struct timeval ts;     /* time stamp */

		u_int32_t ring_id; /* the ring which provoked the entry */

		/* ring buffer fill level minus ring buffer reference fill level */
		int buffer_target_deviation;

		/* controller values for this packet */
		struct cctrack_pid_controller pid;

		/* the sampling limit which was calculated from @pid */
		uint32_t sampling_limit;
	}dyn_sampling_stats[CCTRACK_STATS_PID_MAX];
};



/* ****************  global vars  ******************** */
static struct cctrack_stats_pid *cctrack_stats_pid = NULL;
static struct cctrack_stats_pid *cctrack_stats_pid_read = NULL;
static DEFINE_SPINLOCK(cctrack_stats_pid_lock);
// cctrack_stats_read is the buffer the /proc filesystem is currently
// reading from while cctrack_stats is filled with data
// they are exchanged on read.

#define CCTRACK_ASSERT_STATS_CONSISTENT do{\
	cctrack_assert(cctrack_stats_pid != NULL && cctrack_stats_pid_read != NULL \
			&& cctrack_stats_pid != cctrack_stats_pid_read);\
	}while(0)


//mutex for reading file from userspace
static DEFINE_MUTEX(cctrack_stats_pid_proc_mutex);

static const struct file_operations proc_cctrack_stats_operations = {
		.open           = cctrack_open,
		.read           = seq_read,
		.llseek         = seq_lseek,
		.release        = seq_release,
};

// save the timestamp when the stats were initialized. Necessary to
// shift the time to a gnuplot compatible date
static long cctrack_stats_ts_init;


// print warning when timestamp exceeds 32bit
// not a perfect solution, warning may be printed multiple times
static bool gnuplot_warning_printed = false;


/* ****************  function for /proc interface  ******************** */
/* @see /Documentation/filesystems/seq_file.txt */


/* The iterator is a simple index into the stats array */
static void *cctrack_seq_start(struct seq_file *s, loff_t *pos)
{
	loff_t *spos;
	//printk("cctrack_seq_start %lld \n", *pos);

	mutex_lock(&cctrack_stats_pid_proc_mutex);

	spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
	cctrack_assert(spos != NULL);
	if (! spos){
		return NULL;
	}

	if(*pos >= CCTRACK_STATS_PID_MAX){
		return NULL;
	}


	spin_lock_bh(&cctrack_stats_pid_lock);
		if(*pos == 0 && cctrack_stats_pid->dyn_sampling_stats_limit == 0){
			//no new stats
			spin_unlock_bh(&cctrack_stats_pid_lock);
			return NULL;
		}

		if(*pos != 0 &&
				*pos >= cctrack_stats_pid_read->dyn_sampling_stats_limit){
			//no more old data left to read
			spin_unlock_bh(&cctrack_stats_pid_lock);
			return NULL;
		}

		if(*pos == 0){
			//init
			struct cctrack_stats_pid *tmp_ptr;
			CCTRACK_ASSERT_STATS_CONSISTENT;

			//printk("cctrack_seq_start init \n");

			cctrack_stats_pid->num_packets = cctrack_stats_pid_read->num_packets;
			cctrack_stats_pid->num_packets +=
					cctrack_stats_pid_read->dyn_sampling_stats_limit;


			//swap stats to have a read copy
			tmp_ptr = cctrack_stats_pid;
			cctrack_stats_pid = cctrack_stats_pid_read;
			cctrack_stats_pid_read = tmp_ptr;


			cctrack_assert_after3nd(cctrack_stats_pid->num_packets != 0);
			cctrack_assert_after2nd(
					cctrack_stats_pid_read->dyn_sampling_stats_limit != 0);

			//reset working copy
			cctrack_stats_pid->dyn_sampling_stats_limit = 0;
			atomic_set(&cctrack_stats_pid->status, 0);

			// /proc reads from cctrack_stats_read
		}

		CCTRACK_ASSERT_STATS_CONSISTENT;
	spin_unlock_bh(&cctrack_stats_pid_lock);

	*spos = *pos;

	gnuplot_warning_printed = false;

	return spos;
}

static void *cctrack_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	loff_t *spos = (loff_t *) v;
	//printk("cctrack_seq_next %lld %lld\n", *spos, *pos);
	*pos = ++(*spos);


	if(*pos >= CCTRACK_STATS_PID_MAX){
		return NULL;
	}

	//no lock as read only copy
	if(*pos >= cctrack_stats_pid_read->dyn_sampling_stats_limit){
		spos = NULL;
	}

	return spos;
}


static void cctrack_seq_stop(struct seq_file *s, void *v)
{
	loff_t spos;

	//printk("cctrack_seq_stop %p\n", v);

	//no lock spin_lock_bh(&cctrack_stats_pid_lock);
	if(v != NULL){
		spos = *((loff_t *) v);

		cctrack_assert((s64)cctrack_stats_pid_read->dyn_sampling_stats_limit >=
				(s64)spos);


		if(spos == cctrack_stats_pid_read->dyn_sampling_stats_limit){
			//all stats were read
			//printk("all packets read\n");
		}
	}

	//no lock spin_unlock_bh(&cctrack_stats_pid_lock);

	if(v != NULL){
		kfree(v);
	}

	mutex_unlock(&cctrack_stats_pid_proc_mutex);
}


/* will be called when reading the proc file */
static int cctrack_seq_show(struct seq_file *s, void *v)
{
	unsigned int i;
	loff_t pos = *((loff_t *)v);

	/*
	 * Gnuplot cannot handle 64bit timestamps. However, the accuracy
	 * must be in USEC, thus the time in SEC is multiplied by
	 * USEC_PER_SEC and the time in USEC is added.
	 * To make this gnuplot compatible, the resulting time is shifted to
	 * the year 2000 (approximately).
	 */

	// do not print real time but something gnuplot can understand
	long time_for_gnuplot;
	const long off_to_2k = 946684800; //offset to 2000-01-01 00:00:00

	cctrack_assert(s->private == NULL);
	cctrack_assert(v != NULL);

	//printk("cctrack_seq_show %lld \n", pos);

	cctrack_assert(pos < CCTRACK_STATS_PID_MAX);

	//no lock as read only copy spin_lock_bh(&cctrack_stats_lock);
	cctrack_assert(pos < cctrack_stats_pid_read->dyn_sampling_stats_limit);

	i = pos;
	cctrack_assert(i == pos);


	if(i==0){
		seq_printf(s, "# cctrack PID controller stats\n");
		if(atomic_read(&cctrack_stats_pid_read->status) == 0){
			seq_printf(s, "# no errors logged\n");
		}else if(atomic_read(&cctrack_stats_pid_read->status) == 2){
			seq_printf(s, "# error: stats buffer went full, only the first %d "
					"packets were logged\n", CCTRACK_STATS_PID_MAX);
		}else{
			seq_printf(s, "# ERROR\nstatus was %d\n",
					atomic_read(&cctrack_stats_pid_read->status));
		}
		seq_printf(s, "# packet: NR_not_discarded "
				"time: USEC_since_start+const_offset UNIX_TIMESTAMP "
				"buffer-deviation: Bytes ring: uint "
				"-- proportional: K_P integral: K_I"
				"derivative: K_D -- sampling_limit: Bytes\n");
	}

	time_for_gnuplot = cctrack_stats_pid_read->dyn_sampling_stats[i].ts.tv_sec;
	time_for_gnuplot -= cctrack_stats_ts_init; // relative timestamp
	time_for_gnuplot *= USEC_PER_SEC;
	time_for_gnuplot += cctrack_stats_pid_read->dyn_sampling_stats[i].ts.tv_usec;
	time_for_gnuplot += off_to_2k;

	if(!(time_for_gnuplot <= INT_MAX && time_for_gnuplot >= INT_MIN)){
		if(!gnuplot_warning_printed){
			gnuplot_warning_printed = true;
			seq_printf(s, "============ CUT HERE ================= \n"
					"time does not fit in 32 bits anymore ...\n"
					"=============================================\n");
		}
	}

	seq_printf(s, "%llu %lu %lu %d %u -- "
			"\t%d\t%d\t%d\t"
			"-- %u\n",
			cctrack_stats_pid_read->num_packets + i,
			time_for_gnuplot,
			cctrack_stats_pid_read->dyn_sampling_stats[i].ts.tv_sec,
			cctrack_stats_pid_read->dyn_sampling_stats[i].buffer_target_deviation,
			cctrack_stats_pid_read->dyn_sampling_stats[i].ring_id,
			cctrack_stats_pid_read->dyn_sampling_stats[i].pid.proportional,
			cctrack_stats_pid_read->dyn_sampling_stats[i].pid.integral,
			cctrack_stats_pid_read->dyn_sampling_stats[i].pid.derivate,
			cctrack_stats_pid_read->dyn_sampling_stats[i].sampling_limit
			);

	//no lock as read only copy spin_unlock_bh(&cctrack_stats_lock);

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


/* ****************  init & cleanup functions  ******************** */

/* @returns 0 on success */
int init_cctrack_stats_pid(void){
	struct proc_dir_entry *proc_file;
	struct timeval now;

	cctrack_stats_pid = vmalloc(sizeof(struct cctrack_stats_pid));
	if(cctrack_stats_pid == NULL){
		printk("could not allocate memory for cctrack_stats\n");
		return -1;
	}


	cctrack_stats_pid_read = vmalloc(sizeof(struct cctrack_stats_pid));
	if(cctrack_stats_pid_read == NULL){
		printk("could not allocate memory for cctrack_stats\n");
		vfree(cctrack_stats_pid);
		cctrack_stats_pid = NULL;
		return -1;
	}

	cctrack_assert(cctrack_stats_pid != NULL && cctrack_stats_pid_read != NULL);
	CCTRACK_ASSERT_STATS_CONSISTENT;

	spin_lock_bh(&cctrack_stats_pid_lock);
	/* warn: the following memsets are huge */
	memset(cctrack_stats_pid, 0, sizeof(struct cctrack_stats_pid));
	memset(cctrack_stats_pid_read, 0, sizeof(struct cctrack_stats_pid));
	spin_unlock_bh(&cctrack_stats_pid_lock);

	proc_file = proc_create(CCTRACK_PROC_NAME, 0, NULL, &proc_cctrack_stats_operations);

	if (proc_file == NULL) {
		vfree(cctrack_stats_pid);
		printk("Error: Could not initialize /proc/%s\n", CCTRACK_PROC_NAME);
		return -1;
	}

	do_gettimeofday(&now);
	cctrack_stats_ts_init = now.tv_sec;

	printk("Stats available at /proc/%s\n", CCTRACK_PROC_NAME);

	return 0;
}

void noinline exit_cctrack_stats_pid(void){
	remove_proc_entry(CCTRACK_PROC_NAME, NULL);

	// can't get locks when vfree is running
	spin_lock_bh(&cctrack_stats_pid_lock);
	cctrack_stats_pid->dyn_sampling_stats_limit = 0;
	spin_unlock_bh(&cctrack_stats_pid_lock);

	CCTRACK_ASSERT_STATS_CONSISTENT;

	if(cctrack_stats_pid != NULL){
		vfree(cctrack_stats_pid);
	}
	if(cctrack_stats_pid_read != NULL){
		vfree(cctrack_stats_pid_read);
	}


}


/* ****************  functions  ******************** */

/* must be called from softirq context */
void cctrack_stats_pid_add(int buffer_target_deviation, struct timeval *ts,
		struct cctrack_pid_controller *pid, uint32_t sampling_limit,
		u_int32_t ring_id)
{
	typeof(cctrack_stats_pid->dyn_sampling_stats_limit) limit; //local copy

	if(atomic_read(&cctrack_stats_pid_read->status) == 2){
		//no locks taken
		return;
	}

	spin_lock(&cctrack_stats_pid_lock);

	if(cctrack_stats_pid->dyn_sampling_stats_limit >= CCTRACK_STATS_PID_MAX){
#ifdef DEBUG
		if(atomic_read(&cctrack_stats_pid_read->status) == 0){ //print once
			printk("cctrack_stats overflow! no more data can be recorded! "
					"read /proc/%s to empty buffer\n", CCTRACK_PROC_NAME);
		}
#ifdef DEBUG_VERBOSE
		printk("cctrack_stats overflow\n");
#endif
#endif
		atomic_set(&cctrack_stats_pid_read->status, 2); /* overflow */
		spin_unlock(&cctrack_stats_pid_lock);
		return;
	}

	limit = cctrack_stats_pid->dyn_sampling_stats_limit;


	cctrack_stats_pid->dyn_sampling_stats[limit].buffer_target_deviation =
			buffer_target_deviation;

	cctrack_stats_pid->dyn_sampling_stats[limit].ts.tv_sec = ts->tv_sec;
	cctrack_stats_pid->dyn_sampling_stats[limit].ts.tv_usec = ts->tv_usec;

	cctrack_stats_pid->dyn_sampling_stats[limit].ring_id = ring_id;

	//assertion fails in this version as pid is scaled with module params
	//cctrack_assert(buffer_target_deviation == pid->proportional);

	cctrack_stats_pid->dyn_sampling_stats[limit].pid = *pid;
	cctrack_stats_pid->dyn_sampling_stats[limit].sampling_limit = sampling_limit;

	cctrack_stats_pid->dyn_sampling_stats_limit++;

	spin_unlock(&cctrack_stats_pid_lock);
}

