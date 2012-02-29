/*
 * corny_conntrack_plugin.c
 *
 * Adaptive Low-Level Packet Sampling for High-Speed Networks
 *
 * Authors: L. Braun, C. Diekmann
 *   Chair for Network Architectures and Services
 *   Technische Universitaet Muenchen
 *
 * Acknowledgments to Luca Deri and all contributions of PF_RING!
 * This is a PF_RING-4.7.1 plugin. PF_RING is licensed separately.
 *
 * Copyright (c) 2012, Cornelius Diekmann
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */

#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/textsearch.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>   /* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>


// code which may depend on a specific PF_RING version is marked with
// the following comment */
/* mark PF_RING-a.b.c file.c */
// e.g:
/* mark PF_RING-4.7.1 pf_ring.c */
// the function in pf_ring.c which to refer may be placed below this comment

/* ****************  local includes  ******************** */
/* Enable plugin PF_RING functions */
#define PF_RING_PLUGIN
#include "../linux/pf_ring.h"

#include "corny_conntrack_plugin.h"
#include "cctrack_util.h"
#include "cctrack_hash.h"
#include "cctrack.h"
#include "cctrack_stats.h"
#include "cctrack_stats_generic.h"
#include "cctrack_controller.h"
#include "cctrack_ring_local_storage.h"


/* ****************  local defines  ******************** */
//#define DEBUG_INSERT_OFFSET_TRACING

#ifndef DEBUG
#ifdef DEBUG_INSERT_OFFSET_TRACING
#undef DEBUG_INSERT_OFFSET_TRACING
#endif
#endif

/* ****************  global vars  ******************** */
static struct pfring_plugin_registration reg;

// connection tracking hash-table
static struct cctrack_ht cctrack_ht;

// the number of rings which are registered at this plugin
static atomic_t number_rings;

// ring's cluster id using this plugin, only one cluster id allowed.
static u_short this_cluster_id;
static DEFINE_SPINLOCK(this_cluster_id_lock);


// the scaling of the controler
static struct cctrack_pid_controller_params controller_params = {
		/* default values for a desired default sample_limit of 1500 bytes */
		.K_P_dividend = 1463,
		.K_P_divisor = -1,
		.K_P_divisor_extra = 0,

		.K_I_dividend = 1,
		.K_I_divisor = 2097152,

		.K_D_dividend = 1,
		.K_D_divisor = -1,
		.K_D_divisor_extra = 0,
};


/* ****************  Module Parameters  ******************** */

// connection timeout in seconds
int timeout = 60;
/* not writable but appears in sysfs */
module_param(timeout, int, 0444);
MODULE_PARM_DESC(timeout, "Connection timeout in seconds. Default 60s.");


// sample limit in bytes
int sample_limit = 1500;
/* not writable but appears in sysfs */
module_param(sample_limit, int, 0444);
MODULE_PARM_DESC(sample_limit, "Sample limit in bytes. Default 1500.");

// hashtable size in bytes
static long ht_size = 512*sizeof(bucket);
/* not writable but appears in sysfs */
module_param(ht_size, long, 0444);
MODULE_PARM_DESC(ht_size, "Max hashtable size in bytes. "
		"Default 512*sizeof(bucket).");


//target ring buffer fill level will be ring_size/buffer_target_fill_level
static unsigned int buffer_target_fill_level = 4;
/* not writable but appears in sysfs */
module_param(buffer_target_fill_level, int, 0444);
MODULE_PARM_DESC(buffer_target_fill_level,
	"Target ring buffer fill level will be ring_size/buffer_target_fill_level. "
	"Default 4, meaning buffer should be filled by one fourth.");


// PID params
// helper macro
#ifdef PID_MODULE_PARAM
#error "PID_MODULE_PARAM already defined"
#endif
#define PID_MODULE_PARAM(name)			   \
		module_param_named(name, controller_params.name, int, 0444)


PID_MODULE_PARAM(K_P_dividend);
MODULE_PARM_DESC(K_P_dividend, "Proportional controller value P is scaled by "
								"(P * K_P_dividend)/K_P_divisor. "
								"Default: 1463");
PID_MODULE_PARAM(K_P_divisor);
MODULE_PARM_DESC(K_P_divisor, "Negative value is translated to "
		"abs(value) * (ring_size - (ring_size/buffer_target_fill_level)) . "
		"Default: -1");


PID_MODULE_PARAM(K_I_dividend);
MODULE_PARM_DESC(K_I_dividend, "Integral controller value I is scaled by "
								"(I * K_I_dividend)/K_I_divisor. "
								"Default: 1");
PID_MODULE_PARAM(K_I_divisor);
MODULE_PARM_DESC(K_I_divisor, "Default: 2097152");


PID_MODULE_PARAM(K_D_dividend);
MODULE_PARM_DESC(K_D_dividend, "Derivate controller value D is scaled by "
								"(D * K_D_dividend)/K_D_divisor. "
								"Default: 1");
PID_MODULE_PARAM(K_D_divisor);
MODULE_PARM_DESC(K_D_divisor, "Negative value is translated to "
		"abs(value) * ring_size . "
		"Default: -1");

#undef PID_MODULE_PARAM


static int inertia = 3;
module_param(inertia, int, 0444);
MODULE_PARM_DESC(inertia,
	"The dynamic sampling is calculated "
	"n = inertia/10*n_old + (10-inertia)/10*n_new\n"
	"Set inertia to 10 to get static sampling with a limit of sample_limit. "
	"inertia in [0,10]. Default: 3");


static unsigned int inertia_pkt = 1;
module_param(inertia_pkt, int, 0444);
MODULE_PARM_DESC(inertia_pkt,
	"The dynamic sampling is calculated for every packet. It will only be "
	"applied after inertia_pkt packets to give the controller a chance to "
	"get feedback for it's new sampling limit choice. "
	"Default: 1");

unsigned int warn_min_sample_rate = 64;
module_param(warn_min_sample_rate, int, 0444);
MODULE_PARM_DESC(warn_min_sample_rate,
	"Warn if the dynamic sampling limit drops below this value. "
	"The warning is echoed once and logged in the generic stats for each "
	"time interval. "
	"Default: 64");

/* ****************  PF_RING functions unused ******************** */

/* softirq context */
static int cctrack_plugin_handle_skb(struct pf_ring_socket *pfr,
		sw_filtering_rule_element *rule,
		sw_filtering_hash_bucket *hash_rule,
		struct pfring_pkthdr *hdr,
		struct sk_buff *skb, int displ,
		u_int16_t filter_plugin_id,
		struct parse_buffer **filter_rule_memory_storage,
		rule_action_behaviour *behaviour)
{
	char buf[32];
	printk("-> cctrack_plugin_handle_skb: this is a filter plugin, "
			"this function should never be called! \n");
#ifdef DEBUG
	printk("-> cctrack_plugin_handle_skb : %s\n", buf);
#endif

	return(0);
}


static int cctrack_plugin_get_stats(struct pf_ring_socket *pfr,
		sw_filtering_rule_element *rule,
		sw_filtering_hash_bucket  *hash_bucket,
		u_char* stats_buffer,
		u_int stats_buffer_len)
{
#ifdef DEBUG
	printk("-> dummy_plugin_get_stats(len=%d)\n", stats_buffer_len);
#endif

	return(0);
}



/* ****************  cctrack helper functions ******************** */

/**
 * fill the con structure with the values from hdr.
 * src_ip:src_port, dst_ip:dst_port are sorted to create connections with the
 * same hash bidirectional
 * @param con output
 * @param hdr input
 */
static void get_sorted_connection(struct connection *con,
		struct pfring_pkthdr *hdr)
{

	/*
	 * src_ip = min{(src_ip|src_port),(dst_ip|dst_port)}
	 * dst_ip = max{(src_ip|src_port),(dst_ip|dst_port)}
	 */

	con->key.ip_type = hdr->extended_hdr.parsed_pkt.ip_version;
	con->key.l4_proto = hdr->extended_hdr.parsed_pkt.l3_proto;
	if(isIPv6(con)){
		struct in6_addr src_ip =  hdr->extended_hdr.parsed_pkt.ip_src.v6;
		uint16_t src_port = hdr->extended_hdr.parsed_pkt.l4_src_port;
		struct in6_addr dst_ip = hdr->extended_hdr.parsed_pkt.ip_dst.v6;
		uint16_t dst_port = hdr->extended_hdr.parsed_pkt.l4_dst_port;


		/* (src_ip|src_port) <= (dst_ip|dst_port) */
		if(
		endian_swap(src_ip.s6_addr32[3]) < endian_swap(dst_ip.s6_addr32[3]) ||
		(src_ip.s6_addr32[3] == dst_ip.s6_addr32[3] &&
		endian_swap(src_ip.s6_addr32[2]) < endian_swap(dst_ip.s6_addr32[2]) ) ||
		(src_ip.s6_addr32[3] == dst_ip.s6_addr32[3] &&
		src_ip.s6_addr32[2] == dst_ip.s6_addr32[2] &&
		endian_swap(src_ip.s6_addr32[1]) < endian_swap(dst_ip.s6_addr32[1]) ) ||
		(src_ip.s6_addr32[3] == dst_ip.s6_addr32[3] &&
		src_ip.s6_addr32[2] == dst_ip.s6_addr32[2] &&
		src_ip.s6_addr32[1] == dst_ip.s6_addr32[1] &&
		endian_swap(src_ip.s6_addr32[0]) < endian_swap(dst_ip.s6_addr32[0]) ) ||
		(src_ip.s6_addr32[3] == dst_ip.s6_addr32[3] &&
		src_ip.s6_addr32[2] == dst_ip.s6_addr32[2] &&
		src_ip.s6_addr32[1] == dst_ip.s6_addr32[1] &&
		src_ip.s6_addr32[0] == dst_ip.s6_addr32[0] &&
		src_port <= dst_port ) )
		{
			con->key.ip_src.v6 = src_ip;
			con->key.ip_dst.v6 = dst_ip;
			con->key.l4_src_port = src_port;
			con->key.l4_dst_port = dst_port;
		}else{
			con->key.ip_src.v6 = dst_ip;
			con->key.ip_dst.v6 = src_ip;
			con->key.l4_src_port = dst_port;
			con->key.l4_dst_port = src_port;
		}
	}else{
		uint32_t src_ip =  hdr->extended_hdr.parsed_pkt.ip_src.v4;
		uint16_t src_port = hdr->extended_hdr.parsed_pkt.l4_src_port;
		uint32_t dst_ip = hdr->extended_hdr.parsed_pkt.ip_dst.v4;
		uint16_t dst_port = hdr->extended_hdr.parsed_pkt.l4_dst_port;

		if(src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port)){
			con->key.ip_src.v4 = src_ip;
			con->key.ip_dst.v4 = dst_ip;
			con->key.l4_src_port = src_port;
			con->key.l4_dst_port = dst_port;
		}else{
			con->key.ip_src.v4 = dst_ip;
			con->key.ip_dst.v4 = src_ip;
			con->key.l4_src_port = dst_port;
			con->key.l4_dst_port = src_port;
		}
	}
}

/* mark PF_RING-4.7.1 pf_ring.c */
/* u_int32_t num_queued_pkts(struct pf_ring_socket *pfr) */
/* copy & paste from PF_RING pf_ring.c */
static inline u_int32_t num_queued_pkts(struct pf_ring_socket *pfr)
{
  // smp_rmb();

  if(pfr->ring_slots != NULL) {
    u_int32_t tot_insert = pfr->slots_info->tot_insert;
    u_int32_t tot_read = pfr->slots_info->tot_read;

    if(tot_insert >= tot_read) {
      return(tot_insert - tot_read);
    } else {
      return(((u_int32_t) - 1) + tot_insert - tot_read);
    }

  } else
    return(0);
}



static inline uint32_t get_ring_size(struct pf_ring_socket *the_ring)
{
	/* mark PF_RING-4.7.1 pf_ring.c */
	/* int check_and_init_free_slot(struct pf_ring_socket *pfr, int off) */
	uint32_t ring_size = the_ring->slots_info->tot_mem - sizeof(FlowSlotInfo);
	cctrack_assert(ring_size > 0);
	return ring_size;
}



#ifdef DEBUG_INSERT_OFFSET_TRACING
//for debugging and verifying correct operation
DEFINE_SPINLOCK(insert_offset_tracing_dbg_lock);
static atomic_t insert_offset_correct = {0};
static atomic_t insert_offset_wrong = {0};
#endif


/* insert_offset_tracing */
static inline void __update_inserted_bytes_since_last_insert_off_update(
		struct pf_ring_socket *pfr, struct pfring_pkthdr *hdr,
		struct cctrack_per_ring_data *ring_local,
		int filtered_packet,
		u_int32_t remove_off)
{
	u_int32_t real_slot_size;
	u_int32_t insert_off;
	u_int32_t slot_len;

	//must be locked: read_lock(&pfr->ring_index_lock);
	// slots_info -> remove_off is managed by userpace and may change
	// unexpectedly.
	// to use it consitently, pass a copy to this function
	//must be locked: spin_lock(ring_local->lock_insert_offset_tracing);

	insert_off = pfr->slots_info->insert_off;
	if(ring_local->last_insert_off != insert_off ||
			ring_local->last_lost_pkt != pfr->slots_info->tot_lost)
	{
		// ring buffer update
#ifdef DEBUG_INSERT_OFFSET_TRACING
#ifdef DEBUG_VERBOSE
		// test if insert_offset_tracing works correct for EVERY guess

		// ring operating normal => insert_offset_tracing works correct
		cctrack_assert((insert_off == 0) ||
				(ring_local->inserted_bytes_since_last_insert_off_update +
						ring_local->last_insert_off)
				== (insert_off /*- pfr->slot_header_len*/)
		);
		//assertion failed
		if(!(
			(insert_off == 0) ||
			(ring_local->inserted_bytes_since_last_insert_off_update +
					ring_local->last_insert_off)
					== (pfr->slots_info->insert_off /*- pfr->slot_header_len*/)
			))
		{
			printk("insert_offset_tracing went wrong: "
					"last_insert_off: %d calculated_insert_off:%d, "
					"real_insert_off:%d "
					"Ring: pid: %d, id: %d (%s),(%s)\n",
					ring_local->last_insert_off,
					(ring_local->inserted_bytes_since_last_insert_off_update +
							ring_local->last_insert_off),
					insert_off,
					pfr->ring_pid, pfr->ring_id,
					pfr->appl_name, pfr->sock_proc_name);
		}
#endif
		cctrack_assert(spin_can_lock(&insert_offset_tracing_dbg_lock));
		spin_lock(&insert_offset_tracing_dbg_lock);
		// test if insert_offset_tracing works in ~99% of the cases
		// plus minus 1000 Bytes
		{
			long err;
			if(insert_off == 0){
				err = 0;
			}else{
				err = ((long)ring_local->inserted_bytes_since_last_insert_off_update +
						(long)ring_local->last_insert_off)
					- (long)(insert_off);
			}
			if(err <= -1000L || err >= 1000L)
			{
				atomic_inc(&insert_offset_wrong);
#ifdef DEBUG_VERBOSE
				printk("insert_offset_tracing went wrong: %ld "
						"last_insert_off: %d calculated_insert_off:%d, "
						"real_insert_off:%d "
						"Ring: pid: %d, id: %d (%s),(%s)\n",
						err,
						ring_local->last_insert_off,
						(ring_local->inserted_bytes_since_last_insert_off_update +
								ring_local->last_insert_off),
						insert_off,
						pfr->ring_pid, pfr->ring_id,
						pfr->appl_name, pfr->sock_proc_name);
#endif
			}else{
				atomic_inc(&insert_offset_correct);
			}
		}

		{
			int wrong = atomic_read(&insert_offset_wrong);
			int correct = atomic_read(&insert_offset_correct);
			int number_of_rings = atomic_read(&number_rings);
			if((wrong > 2*number_of_rings) && ( wrong >= correct ||
					( (correct >= 100) && (wrong >= (correct/100))) ) )
			{
				printk("insert_offset_tracing went wrong: correct %d times; "
						"incorrect %d times\n",
						correct,
						wrong
						);
				//reset
				atomic_set(&insert_offset_wrong, -number_of_rings);
				atomic_set(&insert_offset_correct, 0);
			}
			if(correct >= INT_MAX-1000){
				//reset
				atomic_set(&insert_offset_wrong, -number_of_rings);
				atomic_set(&insert_offset_correct, 0);
			}
		}
		spin_unlock(&insert_offset_tracing_dbg_lock);

#endif /* DEBUG_INSERT_OFFSET_TRACING */

		ring_local->inserted_bytes_since_last_insert_off_update = 0;
		ring_local->last_insert_off = pfr->slots_info->insert_off;
		ring_local->last_lost_pkt = pfr->slots_info->tot_lost;
	}

	/* mark PF_RING-4.7.1 pf_ring.c */
	/* int check_and_init_free_slot(struct pf_ring_socket *pfr, int off) */
	/* logic from check_and_init_free_slot() in pf_ring.c
	 * check if ring is full and packet will be discarded anyways */
	if( (pfr->slots_info->insert_off +
			ring_local->inserted_bytes_since_last_insert_off_update)
			< remove_off)
	{
		if((remove_off - (pfr->slots_info->insert_off +
					ring_local->inserted_bytes_since_last_insert_off_update))
			< (2 * pfr->slots_info->slot_len))
		{
			filtered_packet = 1;
		}
	}else{
		if ((pfr->slots_info->tot_mem - sizeof(FlowSlotInfo) -
			(pfr->slots_info->insert_off +
					ring_local->inserted_bytes_since_last_insert_off_update))
			< (2 * pfr->slots_info->slot_len) && (remove_off == 0))
		{
			filtered_packet = 1;
		}
	}

	// ring buffer and insert_offset not updated, need to trace locally
	if(!filtered_packet){
		/* mark PF_RING-4.7.1 pf_ring.c */
		/* int get_next_slot_offset(struct pf_ring_socket *pfr,
		 * u_int32_t off, u_int32_t *real_off) */
		real_slot_size =  hdr->caplen + hdr->extended_hdr.parsed_header_len;
		real_slot_size += pfr->slot_header_len;

		ring_local->inserted_bytes_since_last_insert_off_update += real_slot_size;
	}

	slot_len = pfr->slots_info->slot_len;

	if(ring_local->inserted_bytes_since_last_insert_off_update > slot_len)
	{
		// we made an error, correct error as good as possible by setting
		// the maximum sound value
		ring_local->inserted_bytes_since_last_insert_off_update = slot_len;
	}

	// we only trace offset inside the slot!
	cctrack_assert(ring_local->inserted_bytes_since_last_insert_off_update
			<= slot_len);

	cctrack_assert(slot_len == pfr->slots_info->slot_len);

	////must be unlocked: spin_unlock(ring_local->lock_insert_offset_tracing);
	//must be unlocked: read_unlock(&pfr->ring_index_lock);

}

/* must be called on each new packet to update the insert_offset_tracing */
static uint32_t get_ring_free_level(struct pf_ring_socket *the_ring,
		struct pfring_pkthdr *hdr, struct cctrack_per_ring_data *ring_local,
		int filtered_packet)
{
	long free = 0;
	u_int32_t insert_off;
	u_int32_t remove_off;

	read_lock(&the_ring->ring_index_lock);
	spin_lock(&ring_local->lock_insert_offset_tracing);

	insert_off = the_ring->slots_info->insert_off;

	// manged by userland, need a local copy for assertions
	// grep that slots_info->remove_off is only used once here
	remove_off = the_ring->slots_info->remove_off;

	/* insert_offset_tracing */
	__update_inserted_bytes_since_last_insert_off_update(the_ring,
			hdr, ring_local, filtered_packet, remove_off);

	if(insert_off == remove_off) {
	    /*
	      Both insert and remove offset are set on the same slot.
	      We need to find out whether the memory is full or empty
	    */
		//printk("insert_off == remove_off\n");

		/* mark PF_RING-4.7.1 pf_ring.c */
		/* int check_and_init_free_slot(struct pf_ring_socket *pfr, int off) */
		if(num_queued_pkts(the_ring) >= pf_ring_get_min_num_slots()){
			/* pf_ring_get_min_num_slots() requires a patch to PF_RING
			 * to return the static global var min_num_slots:
			 * unsigned int pf_ring_get_min_num_slots(void){return min_num_slots;}
			 * EXPORT_SYMBOL(pf_ring_get_min_num_slots);*/
			free = 0; /* Memory is full */
			//printk("full\n");
		}else{
			free = get_ring_size(the_ring);
			//printk("free\n");
		}

	}else if(insert_off > remove_off){
		//printk("insert_off > remove_off");
		free = the_ring->slots_info->tot_mem -insert_off;
		cctrack_assert(free >= 0);
		free += remove_off;
		cctrack_assert(free >= 0);
		free -= sizeof(FlowSlotInfo);
		cctrack_assert(free >= 0);

	}else if(insert_off < remove_off){
		//printk("insert_off < remove_off");
		free = remove_off - insert_off;

	}else{cctrack_assert(0);}

	cctrack_assert(free >= 0);
	cctrack_assert(get_ring_size(the_ring) >= free);

	// insert_off > remove_off => (full <= insert_off - remove_off)
	cctrack_assert(
	!(insert_off > remove_off) ||
	(
		(get_ring_size(the_ring) - free) <= (insert_off - remove_off)
	)
	)

	// insert_off < remove_off => (free <= remove_off - insert_off)
	cctrack_assert(
	!(insert_off < remove_off) ||
	(
		free <= (remove_off - insert_off)
	)
	)

#ifdef DEBUG_VERBOSE
	printk("num_queued_pkts: %u slot_len:%u "
			"lost: %llu "
			"free: %ld inserted_bytes_since_last_insert_off_update:%d "
			"insert_off:%u calculated_insert_off:%d "
			"remove_off:%u\n",
			num_queued_pkts(the_ring), the_ring->slots_info->slot_len,
			the_ring->slots_info->tot_lost,
			free, ring_local->inserted_bytes_since_last_insert_off_update,
			insert_off,
			(ring_local->inserted_bytes_since_last_insert_off_update +
											ring_local->last_insert_off),
			remove_off);
#endif

	free -= (long)ring_local->inserted_bytes_since_last_insert_off_update;

	/* free is greater equal zero or
	 * at least (in the case insert_offset_tracing is wrong) one slot_len
	 * below zero */
	cctrack_assert(free >= 0 || (free >= -((long)the_ring->slots_info->slot_len)));
	if(free < 0){
		//we are wrong by only a few bytes but fix this anyway
		free = 0;
	}

	cctrack_assert((((long)get_ring_size(the_ring)) - free) >= 0);

	//insert_off > remove_off => (full <= insert_off+slot - remove_off)
	cctrack_assert(
	!(insert_off > remove_off) ||
	(
		(get_ring_size(the_ring) - free) <=
		(insert_off + the_ring->slots_info->slot_len - remove_off)
	)
	);

	// insert_off < remove_off => (free <= remove_off - insert_off )
	cctrack_assert(
	!(insert_off < remove_off) ||
	(
		free <= (remove_off - insert_off)
	)
	);

	spin_unlock(&ring_local->lock_insert_offset_tracing);
	read_unlock(&the_ring->ring_index_lock);

	cctrack_assert(free >= 0);
	cctrack_assert(free <= UINT_MAX);

	return free;
}


/**
 * @return
 * negative value: buffer below threshold, buffer almost empty
 * positive value: buffer above threshold, buffer filling
 */
static int get_ring_fill_level_deviation(struct pf_ring_socket *the_ring,
		struct pfring_pkthdr *hdr, struct cctrack_per_ring_data *ring_local,
		int filtered_packet)
{
	uint32_t ring_size = get_ring_size(the_ring);
	uint32_t free = get_ring_free_level(the_ring, hdr, ring_local,
			filtered_packet);
	long full = ring_size - free;
	long res;
	cctrack_assert(full >= 0);

	/* 1/buffer_target_fill_level of the buffer should be filled on default */
	res = full - (long)(ring_size/buffer_target_fill_level);
#ifdef DEBUG_VERBOSE
	printk("get_ring_fill_level_deviation: %ld\n", res);
#endif

	cctrack_assert(res >= INT_MIN && res <= INT_MAX);
	return (int)res;
}


/* get ring local storage, initialize if necessary */
static inline struct cctrack_per_ring_data *get_or_init_ring_local_data(
		struct pf_ring_socket *the_ring)
{
	struct cctrack_per_ring_data *this_ring_data;
	this_ring_data = cctrack_get_ring_storage(the_ring->ring_pid,
			the_ring->ring_id);

	if(this_ring_data == NULL){
		/* allocate ring local storage if not present */
		if(!cctrack_init_new_ring_storage(the_ring->ring_pid,the_ring->ring_id))
		{
			cctrack_printk_once("could not allocate ring local storage for ring "
					"pid: %d, id: %d (%s),(%s)\n"
					"cctrack will no longer work for this and future rings.\n",
					the_ring->ring_pid, the_ring->ring_id,
					the_ring->appl_name, the_ring->sock_proc_name);
			cctrack_printk_once(KERN_ERR "please reload cctrack module!!\n");
			return NULL;
		}else{
			this_ring_data = cctrack_get_ring_storage(the_ring->ring_pid,
					the_ring->ring_id);
			cctrack_assert(this_ring_data != NULL);

#ifdef DEBUG_INSERT_OFFSET_TRACING
			// the first insert_offset_tracing assertion will always fail as
			// this_ring_data is not correctly initialized. The mechanism works
			// nevertheless. Subtract this error to not generate a false
			// positive error reporting
			atomic_dec(&insert_offset_wrong);
#endif

			/* check if only one ring or only one ring cluster is used */
			spin_lock(&this_cluster_id_lock);
			if(atomic_add_return(1, &number_rings) == 1){
				// first registered ring
				this_cluster_id = the_ring->cluster_id;
			}else{
				//registered rings after the first
				if(this_cluster_id == 0 ||
						this_cluster_id != the_ring->cluster_id)
				{
					printk("cctrack error: only one ring or ring cluster "
							"allowed. Trying %d rings with cluster id %d. "
							"Suspected cluster id %d\n",
							atomic_read(&number_rings), the_ring->cluster_id,
							this_cluster_id);
				}
			}
			spin_unlock(&this_cluster_id_lock);
		}
	}
	cctrack_assert(this_ring_data != NULL);
	return this_ring_data;
}

/* ****************  cctrack PID controller functions ******************** */

/*
 * updates the sampling limit. This limit will apply to the next packet.
 * cctrack_ht.ht_lock must NOT be hold.
 * @params pid, values will be updated and scaled!
 * @returns new_sampling_limit
 */
static uint32_t cctrack_update_sampling_limit(struct pf_ring_socket *the_ring,
		struct cctrack_per_ring_data *this_ring_data,
		struct cctrack_pid_controller *pid)
{
	s64 old_sampling_limit;
	s64 new_sampling_limit;
	s32 extra_P;
	s32 extra_D;
	s64 P, I, D;

	/* extra_* are only used when divisor was < 0 */
	extra_P = get_ring_size(the_ring); //unsigned
	extra_D = extra_P;
	cctrack_assert(extra_P > 0 && extra_D > 0);
	extra_P -= extra_P/buffer_target_fill_level;
	cctrack_assert(extra_P > 0);


	//TODO assert pid theoretical min/max

	P = ((s64)controller_params.K_P_dividend *
						(s64)pid->proportional)
						/
						get_pid_divisor_P(&controller_params, extra_P);
	cctrack_assert(P >= INT_MIN && P <= INT_MAX);

	I = ((s64)controller_params.K_I_dividend *
			(s64)pid->integral)
			/
			get_pid_divisor_I(&controller_params);
	cctrack_assert(I >= INT_MIN && I <= INT_MAX);

	D = ((s64)controller_params.K_D_dividend *
				(s64)pid->derivate)
				/
				get_pid_divisor_D(&controller_params, extra_D);
	cctrack_assert(D >= INT_MIN && D <= INT_MAX);

	new_sampling_limit = P + I + D;

	//update for statistics
	pid->proportional = (s32)P;
	pid->integral = (s32)I;
	pid->derivate = (s32)D;

	// new_sampling_limit < 0  => buffer empty
	// new_sampling_limit > 0  => buffer full

	//assertion may fail if params are chosen poorly
	cctrack_assert(!(new_sampling_limit < 0L) ||
			(sample_limit - new_sampling_limit > 0L));

	new_sampling_limit = ((s64)sample_limit) - new_sampling_limit;


	cctrack_assert(new_sampling_limit >= INT_MIN &&
			new_sampling_limit <= UINT_MAX);
	cctrack_assert(!(new_sampling_limit > 0L) ||
			new_sampling_limit == (new_sampling_limit & 0xFFFFFFFFL));

	if(new_sampling_limit < 64) new_sampling_limit = 64;
	if(new_sampling_limit >= 0x80000000L) new_sampling_limit = 0x7FFFFFFFL;
	cctrack_assert(new_sampling_limit == (new_sampling_limit & 0x7FFFFFFFL));

	write_lock(&this_ring_data->vars.lock);
		cctrack_assert(this_ring_data->vars.inertia_pkt_cnt < inertia_pkt);

		old_sampling_limit = this_ring_data->vars.sampling_limit_fut;
		new_sampling_limit = (old_sampling_limit*((s64)inertia))/10 +
				(new_sampling_limit*((s64)(10-inertia)))/10;
		if(new_sampling_limit < 64) new_sampling_limit = 64;
		if(new_sampling_limit >= 0x80000000L) new_sampling_limit = 0x7FFFFFFFL;

		if(++this_ring_data->vars.inertia_pkt_cnt == inertia_pkt){
			//update new sampling limit
			this_ring_data->vars.sampling_limit_fut = (uint32_t)new_sampling_limit;
			this_ring_data->vars.sampling_limit = (uint32_t)new_sampling_limit;
			this_ring_data->vars.inertia_pkt_cnt = 0;
		}else{
			//only calculate sampling limit for later use
			this_ring_data->vars.sampling_limit_fut = (uint32_t)new_sampling_limit;

			//return old limit
			new_sampling_limit = this_ring_data->vars.sampling_limit;
		}
	write_unlock(&this_ring_data->vars.lock);

	cctrack_assert(new_sampling_limit == (new_sampling_limit & 0x7FFFFFFFL));
	cctrack_assert(new_sampling_limit >= 0);
	cctrack_assert(new_sampling_limit <= UINT_MAX);
	cctrack_assert(new_sampling_limit <= INT_MAX);

	return (uint32_t)new_sampling_limit;
}



/* ****************  main PF_RING handler ******************** */

/**
 * @return Zero if the packet has not matched the rule filter,
 *  a positive value otherwise.
 *  */
static int cctrack_plugin_filter(struct pf_ring_socket *the_ring,
		sw_filtering_rule_element *rule,
		struct pfring_pkthdr *hdr,
		struct sk_buff *skb, int displ,
		struct parse_buffer **parse_memory)
{
	struct connection con;
	struct connection *bucket;
	int cond;
	int ret;
	int ring_deviation;
	struct cctrack_pid_controller pid;
	struct cctrack_per_ring_data *this_ring_data;

	/* get ring local storage */
	this_ring_data = get_or_init_ring_local_data(the_ring);
	if(this_ring_data == NULL){
		cctrack_printk_once("ERROR (FATAL):"
				"get_or_init_ring_local_data failed (cctrack)\n");
		return 0;
	}

	cctrack_stats_generic_add_every_pkt(&hdr->ts);

	/* check packet type */
	if(hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /*ipv4*/ ||
		hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /*ipv6*/)
	{

		if(hdr->extended_hdr.parsed_pkt.offset.l3_offset != 0){
			get_sorted_connection(&con, hdr);
		}
	}else if(hdr->extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */){
		return(0);
	}else{
		printk("Unknown eth type : %d\n",
				hdr->extended_hdr.parsed_pkt.eth_type);

		return(0); /* no match */
	}
#ifdef DEBUG_VERBOSE
		printk("-> cctrack_plugin_filter\n");
#endif


	/* insert/update connection tracking hash table */
	spin_lock(&cctrack_ht.ht_lock);

	bucket = cctrack_qiuConnection(&cctrack_ht, &con);
	if(bucket == NULL){
		cctrack_printk_once("hashtable error (full)\n");
#ifdef DEBUG_VERBOSE
		dbg_printTable(&cctrack_ht);
#endif

		spin_unlock(&cctrack_ht.ht_lock);
		return(0);
	}

	bucket->timestamp = hdr->ts.tv_sec;

	read_lock(&this_ring_data->vars.lock);
	cond = bucket->bytes_sampled > this_ring_data->vars.sampling_limit;
	read_unlock(&this_ring_data->vars.lock);

//TODO remove dirty hack
#define DIRTY_STATS_HACK_ETHERNET_HDR
#ifdef DIRTY_STATS_HACK_ETHERNET_HDR
{
	int hacky_i;
	uint32_t hacky_bytessampled;
	int hack_cond;
	for(hacky_i=0; hacky_i < ETH_ALEN; ++hacky_i){
		hdr->extended_hdr.parsed_pkt.dmac[hacky_i]=0;
		hdr->extended_hdr.parsed_pkt.smac[hacky_i]=0;
	}

	read_lock(&this_ring_data->vars.lock);
	hack_cond = bucket->bytes_sampled + (hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.l4_offset) > this_ring_data->vars.sampling_limit;
	read_unlock(&this_ring_data->vars.lock);
	//dst 0 == flow geht weiter
	//dst 1 == letztes packet
	memcpy(&hdr->extended_hdr.parsed_pkt.dmac, &hack_cond, sizeof(hack_cond));

	hacky_bytessampled = bucket->bytes_sampled +
			(hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.l4_offset);

	memcpy(&hdr->extended_hdr.parsed_pkt.smac, &hacky_bytessampled, sizeof(hacky_bytessampled));
}
#endif /* DIRTY_STATS_HACK_ETHERNET_HDR */

	if(cond){
		/* stream completely sampled */
		bucket->bytes_sampled = 0xffffffff;
		ret = 1; /* match */
	}else{
		//printk("payload offset:%d  l4 offset:%d\n",
		//		hdr->extended_hdr.parsed_pkt.offset.payload_offset,
		//		hdr->extended_hdr.parsed_pkt.offset.l4_offset);
		//printk("payload:%d  l4+payload:%d\n",
		//	hdr->caplen	- hdr->extended_hdr.parsed_pkt.offset.payload_offset,
		//	hdr->caplen	- hdr->extended_hdr.parsed_pkt.offset.l4_offset);

		bucket->bytes_sampled +=
				(hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.l4_offset);
		cctrack_assert((uint32_t)hdr->extended_hdr.parsed_pkt.offset.l4_offset
				== hdr->extended_hdr.parsed_pkt.offset.l4_offset);
		ret = 0; /* no match */
	}

	spin_unlock(&cctrack_ht.ht_lock);


	/* insert_offset_tracing */
	ring_deviation = get_ring_fill_level_deviation(the_ring,
			hdr, this_ring_data, ret);
	if(!ret){
		uint32_t new_sampling_limit;
		/* only go on if this packet is not discarded */

		/* update controller */
		cctrack_controller_new_packet(this_ring_data,
				hdr->ts, ring_deviation, &pid);

		/* In fact, the pid values calculated for the current packet are
		 * applied to the next packet. This is more accurate as it is already
		 * decided whether to discard this packet. */
		new_sampling_limit = cctrack_update_sampling_limit(the_ring,
				this_ring_data, &pid);

		/* update stats */
		cctrack_stats_pid_add(ring_deviation, &hdr->ts, &pid,
				new_sampling_limit, the_ring->ring_id);

		cctrack_stats_generic_add_sampled_pkt(&hdr->ts, new_sampling_limit);
	}

	return ret;
}




/* ****************  PF_RING setup ******************** */

static void cctrack_plugin_register(u_int8_t register_plugin) {
	if(register_plugin){
		try_module_get(THIS_MODULE); /* Increment usage count */
#ifdef DEBUG
		printk("-> cctrack_plugin_register register\n");
#endif
	}else{
		module_put(THIS_MODULE);	 /* Decrement usage count */
#ifdef DEBUG
		printk("-> cctrack_plugin_register unregister\n");
#ifdef DEBUG_VERBOSE
		dbg_printTable(&cctrack_ht);
#endif
#endif
	}
}



/* ****************  module init & exit ******************** */

static int __init cctrack_plugin_init(void)
{
	s64 tmpint = 0;
	s64 P = 0;
	s64 I = 0;
	s64 D = 0;
	s32 __ring_size;
	atomic_set(&number_rings, 0);


	printk("Welcome to cctrack plugin for PF_RING\n");

	cctrack_assert(sample_limit < INT_MAX);
	cctrack_assert(buffer_target_fill_level < INT_MAX);
	cctrack_assert(inertia_pkt < INT_MAX);


	cctrack_assert(warn_min_sample_rate < INT_MAX);

	/* check and set controller_params */
	if(controller_params.K_P_divisor == 0){
		printk("error: K_P_divisor == 0\n");
		return -1;
	}
	if(controller_params.K_I_divisor == 0){
		printk("error: K_I_divisor == 0\n");
		return -1;
	}
	if(controller_params.K_D_divisor == 0){
		printk("error: K_D_divisor == 0\n");
		return -1;
	}

	//check if something is disabled
	if(controller_params.K_P_dividend == 0){
		printk("warning: K_P_dividend == 0 (disabled P)\n");
	}
	if(controller_params.K_I_dividend == 0){
		printk("warning: K_I_dividend == 0 (disabled I)\n");
	}
	if(controller_params.K_D_dividend == 0){
		printk("warning: K_D_dividend == 0 (disabled D)\n");
	}

	if(controller_params.K_P_dividend < 0){
		printk("warning: K_P_dividend < 0\n");
	}
	if(controller_params.K_I_dividend < 0){
		printk("warning: K_I_dividend < 0\n");
	}
	if(controller_params.K_D_dividend < 0){
		printk("warning: K_D_dividend < 0\n");
	}


	if(controller_params.K_P_divisor < 0){
		controller_params.K_P_divisor *= -1;
		controller_params.K_P_divisor_extra = 1;
	}
	if(controller_params.K_I_divisor < 0){
		printk("error: K_I_divisor < 0\n");
		return -1;
	}
	if(controller_params.K_D_divisor < 0){
		controller_params.K_D_divisor *= -1;
		controller_params.K_D_divisor_extra = 1;
	}

	// prevent overflows
	cctrack_assert(controller_params.K_P_dividend < 4194304);
	cctrack_assert(controller_params.K_I_dividend < 4194304);
	cctrack_assert(controller_params.K_D_dividend < 4194304);

	cctrack_assert(controller_params.K_P_divisor > 0);
	cctrack_assert(controller_params.K_I_divisor > 0);
	cctrack_assert(controller_params.K_D_divisor > 0);

	//checks inside the get_pid_divisor_X functions
	cctrack_assert(get_pid_divisor_P(&controller_params, 1) > 0);
	cctrack_assert(get_pid_divisor_D(&controller_params, 1) > 0);

	if(inertia < 0 || inertia > 10){
		printk("inertia must be in [0,10]\n");
		return -1;
	}

	//print PID controlled system formula
	printk("Resulting controlled system:\n");
	printk("\ts: ring buffer size\n"
			"\ttarget_fill_level: 1/%d (buffer_target_fill_level)\n"
			"\tP,I,D: pid controller values calculated for each packet\n",
			buffer_target_fill_level);
	printk("\tn_new = ");
	printk("(%d * P)/(%d%s) + ",
			controller_params.K_P_dividend, controller_params.K_P_divisor,
			controller_params.K_P_divisor_extra ?
					" * (s-(s/target_fill_level))" : "");
	printk("(%d * I)/(%d) + ",
			controller_params.K_I_dividend, controller_params.K_I_divisor);
	printk("(%d * D)/(%d%s)\n",
			controller_params.K_D_dividend, controller_params.K_D_divisor,
			controller_params.K_D_divisor_extra ?
					" * s" : "");
	printk("\tn = %d/10 * n_old + %d/10 * n_new\n", inertia, 10-inertia);

	/*calculate maximum sampling limit achievable by native controller */
	/* for a assumed ring size of 134217728 (Tot Memory) */
	__ring_size =134217728;
	P = ((s64)controller_params.K_P_dividend *
			(-(s64)(__ring_size/buffer_target_fill_level)))
			/
			get_pid_divisor_P(&controller_params,
					(__ring_size - (__ring_size/buffer_target_fill_level)));
	cctrack_assert(P >= INT_MIN && P <= INT_MAX);

	I = ((s64)controller_params.K_I_dividend *
			(s64)INT_MIN)
			/
			get_pid_divisor_I(&controller_params);
	cctrack_assert(I >= INT_MIN && I <= INT_MAX);

	D = ((s64)controller_params.K_D_dividend *
			(s64)(-1000*__ring_size))
			/
			get_pid_divisor_D(&controller_params, __ring_size);
	cctrack_assert(D >= INT_MIN && D <= INT_MAX);

	tmpint = P + I + D;
	tmpint = sample_limit - tmpint;

	printk("\twith a ring size of %d the max sampling limit is %lld\n",
			__ring_size, tmpint);
	printk("\tmax\tP:%lld I:%lld D:%lld\n\n", P, I, D);

	//END

	/* create hashtable */

	printk("Hashtable: requested %lu byte, %lu kbyte, %lu mbyte\n",
			ht_size, ht_size/1024, ht_size/(1024*1024));
	ht_size = cctrack_get_number_of_buckets(ht_size);
	printk("Hashtable buckets: %lu\n", ht_size);
	printk("Hashtable final size: %lu byte, %lu kbyte, %lu mbyte\n",
			ht_size*sizeof(bucket),
			ht_size*sizeof(bucket)/1024, ht_size*sizeof(bucket)/(1024*1024));

	if(cc_create_hashtable(&cctrack_ht, ht_size) != 0) return -1;

	printk("Hashtable size bitmask: 0x%x\n", cctrack_ht.size_bitmask);
	spin_lock_init(&cctrack_ht.ht_lock);


	/* init ring local data */
	cctrack_ring_local_storage_init();


	printk("sampling limit:%d\ntimeout: %d\n", sample_limit, timeout);
	cctrack_ht.initval1 = 0;
	cctrack_ht.initval2 = 0x12345678;

	if(cctrack_ht.initval1 == cctrack_ht.initval2){
		printk("initval1 and 2 are equal, hashtable will behave poor\n");
	}

	/* set up stats */
	if(init_cctrack_stats_pid() != 0){
		printk("could not init cctrack_stats\n");
		vfree(cctrack_ht.ht);
		return -1;
	}

	/* set up stats dynamic */
	if(init_cctrack_stats_generic() != 0){
		printk("could not init cctrack_stats_generic\n");
		vfree(cctrack_ht.ht);
		exit_cctrack_stats_pid();
		return -1;
	}

	/* set up controller */
	cctrack_controller_init();

	/* register plugin at PF_RING */
	memset(&reg, 0, sizeof(reg));

	reg.plugin_id                = CCTRACK_PLUGIN_ID;
	reg.pfring_plugin_handle_skb = cctrack_plugin_handle_skb;
	reg.pfring_plugin_get_stats  = cctrack_plugin_get_stats;
	reg.pfring_plugin_filter_skb = cctrack_plugin_filter;
	reg.pfring_plugin_register   = cctrack_plugin_register;

	snprintf(reg.name, sizeof(reg.name)-1, "cctrack");
	snprintf(reg.description, sizeof(reg.description)-1,
			"cctrack: corny connection tracking");

	register_plugin(&reg);

	/* Make sure that PF_RING is loaded when this plugin is loaded */
	pf_ring_add_module_dependency();

	printk("cctrack plugin started [id=%d]\n", CCTRACK_PLUGIN_ID);
	return(0);
}


static void __exit cctrack_plugin_exit(void)
{
	int i;

	printk("Thanks for having used cctrack plugin for PF_RING\n");

	unregister_plugin(CCTRACK_PLUGIN_ID);
	printk("1\n");


	// testing workaround for kernel panics when unloading
	printk("sleeping a bit to make sure possible threads still within cctrack "
			"return\n");
	for(i=0; i<100000; ++i){
		//get and release some locks
		spin_lock_bh(&cctrack_ht.ht_lock);
		spin_unlock_bh(&cctrack_ht.ht_lock);
		schedule();
	}

	cctrack_controller_exit();
	printk("2\n");

	vfree(cctrack_ht.ht);
	printk("3\n");
	exit_cctrack_stats_pid();
	printk("4\n");
	exit_cctrack_stats_generic();
	printk("5\n");

	cctrack_ring_local_storage_exit();
	printk("6\n");
}


module_init(cctrack_plugin_init);
module_exit(cctrack_plugin_exit);
MODULE_LICENSE("Dual BSD/GPL"); /* BSD is GPL compatible and this does not taint your kernel. */
MODULE_AUTHOR("Cornelius Diekmann <diekmann@in.tum.de>");
MODULE_DESCRIPTION("Plugin for PF_RING kernel module");
MODULE_VERSION("0.5-dynsampling");
