/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBE_H_
#define _IXGBE_H_

#ifndef IXGBE_NO_LRO
#include <net/tcp.h>
#endif

#include <linux/pci.h>
#include <linux/netdevice.h>

#ifdef DISABLE_NETIF_F_HW_VLAN_TX
#undef NETIF_F_HW_VLAN_TX
#endif

#ifdef HAVE_IRQ_AFFINITY_HINT
#include <linux/cpumask.h>
#endif /* HAVE_IRQ_AFFINITY_HINT */
#include <linux/vmalloc.h>

#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif
#ifdef NETIF_F_HW_VLAN_TX
#include <linux/if_vlan.h>
#endif
#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
#define IXGBE_DCA
#include <linux/dca.h>
#endif
#include "ixgbe_dcb.h"

#include "kcompat.h"

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
#define IXGBE_FCOE
#include "ixgbe_fcoe.h"
#endif /* CONFIG_FCOE or CONFIG_FCOE_MODULE */

#include "ixgbe_api.h"

#define PFX "ixgbe: "
#define DPRINTK(nlevel, klevel, fmt, args...) \
	((void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
	printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
		__FUNCTION__ , ## args)))

/* TX/RX descriptor defines */
#define IXGBE_DEFAULT_TXD		    512
#define IXGBE_MAX_TXD			   4096
#define IXGBE_MIN_TXD			     64

#define IXGBE_DEFAULT_RXD		    512
#define IXGBE_MAX_RXD			   4096
#define IXGBE_MIN_RXD			     64


/* flow control */
#define IXGBE_MIN_FCRTL			   0x40
#define IXGBE_MAX_FCRTL			0x7FF80
#define IXGBE_MIN_FCRTH			  0x600
#define IXGBE_MAX_FCRTH			0x7FFF0
#define IXGBE_DEFAULT_FCPAUSE		 0xFFFF
#define IXGBE_MIN_FCPAUSE		      0
#define IXGBE_MAX_FCPAUSE		 0xFFFF

/* Supported Rx Buffer Sizes */
#define IXGBE_RXBUFFER_512   512    /* Used for packet split */
#define IXGBE_RXBUFFER_2048  2048
#define IXGBE_RXBUFFER_4096  4096
#define IXGBE_RXBUFFER_8192  8192
#define IXGBE_MAX_RXBUFFER   16384  /* largest size for single descriptor */

/*
 * NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN mans we
 * reserve 2 more, and skb_shared_info adds an additional 384 bytes more,
 * this adds up to 512 bytes of extra data meaning the smallest allocation
 * we could have is 1K.
 * i.e. RXBUFFER_512 --> size-1024 slab
 */
#define IXGBE_RX_HDR_SIZE IXGBE_RXBUFFER_512

#define MAXIMUM_ETHERNET_VLAN_SIZE (VLAN_ETH_FRAME_LEN + ETH_FCS_LEN)

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IXGBE_RX_BUFFER_WRITE	16	/* Must be power of 2 */

#define IXGBE_TX_FLAGS_CSUM		(u32)(1)
#define IXGBE_TX_FLAGS_HW_VLAN		(u32)(1 << 1)
#define IXGBE_TX_FLAGS_SW_VLAN		(u32)(1 << 2)
#define IXGBE_TX_FLAGS_TSO		(u32)(1 << 3)
#define IXGBE_TX_FLAGS_IPV4		(u32)(1 << 4)
#define IXGBE_TX_FLAGS_FCOE		(u32)(1 << 5)
#define IXGBE_TX_FLAGS_FSO		(u32)(1 << 6)
#define IXGBE_TX_FLAGS_TXSW		(u32)(1 << 7)
#define IXGBE_TX_FLAGS_MAPPED_AS_PAGE	(u32)(1 << 8)
#define IXGBE_TX_FLAGS_VLAN_MASK	0xffff0000
#define IXGBE_TX_FLAGS_VLAN_PRIO_MASK	0xe0000000
#define IXGBE_TX_FLAGS_VLAN_PRIO_SHIFT  29
#define IXGBE_TX_FLAGS_VLAN_SHIFT	16

#define IXGBE_MAX_RX_DESC_POLL          10

#define IXGBE_MAX_RSC_INT_RATE          162760

#define IXGBE_MAX_VF_MC_ENTRIES         30
#define IXGBE_MAX_VF_FUNCTIONS          64
#define IXGBE_MAX_VFTA_ENTRIES          128
#define MAX_EMULATION_MAC_ADDRS         16

#define UPDATE_VF_COUNTER_32bit(reg, last_counter, counter)	\
	{							\
		u32 current_counter = IXGBE_READ_REG(hw, reg);	\
		if (current_counter < last_counter)		\
			counter += 0x100000000LL;		\
		last_counter = current_counter;			\
		counter &= 0xFFFFFFFF00000000LL;		\
		counter |= current_counter;			\
	}

#define UPDATE_VF_COUNTER_36bit(reg_lsb, reg_msb, last_counter, counter) \
	{								 \
		u64 current_counter_lsb = IXGBE_READ_REG(hw, reg_lsb);	 \
		u64 current_counter_msb = IXGBE_READ_REG(hw, reg_msb);	 \
		u64 current_counter = (current_counter_msb << 32) |      \
			current_counter_lsb;                             \
		if (current_counter < last_counter)			 \
			counter += 0x1000000000LL;			 \
		last_counter = current_counter;				 \
		counter &= 0xFFFFFFF000000000LL;			 \
		counter |= current_counter;				 \
	}

struct vf_stats {
	u64 gprc;
	u64 gorc;
	u64 gptc;
	u64 gotc;
	u64 mprc;
};

struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	u16 vf_mc_hashes[IXGBE_MAX_VF_MC_ENTRIES];
	u16 num_vf_mc_hashes;
	u16 default_vf_vlan_id;
	u16 vlans_enabled;
	bool clear_to_send;
	struct vf_stats vfstats;
	struct vf_stats last_vfstats;
	struct vf_stats saved_rst_vfstats;
	bool pf_set_mac;
	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
	u16 pf_qos;
};

#ifndef IXGBE_NO_LRO
#define IXGBE_LRO_MAX 32	/*Maximum number of LRO descriptors*/
#define IXGBE_LRO_GLOBAL 10

struct ixgbe_lro_stats {
	u32 flushed;
	u32 coal;
	u32 recycled;
};

struct ixgbe_lro_desc {
	struct  hlist_node lro_node;
	struct  sk_buff *skb;
	__be32  source_ip;
	__be32  dest_ip;
	__be16  source_port;
	__be16  dest_port;
	__be32  ack_seq;
	__be16  window;
	u16     mss;
	u16     vlan_tag;
	u16     len;
	u32     next_seq;
	u16     opt_bytes;
	u16     psh:1;
	u32     tsval;
	__be32  tsecr;
	u32     append_cnt;
};

struct ixgbe_lro_list {
	struct hlist_head active;
	struct hlist_head free;
	int active_cnt;
	struct ixgbe_lro_stats stats;
};

#endif /* IXGBE_NO_LRO */

#define IXGBE_MAX_TXD_PWR	14
#define IXGBE_MAX_DATA_PER_TXD	(1 << IXGBE_MAX_TXD_PWR)

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S) DIV_ROUND_UP((S), IXGBE_MAX_DATA_PER_TXD)
#ifdef MAX_SKB_FRAGS
#define DESC_NEEDED ((MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE)) + 4)
#else
#define DESC_NEEDED 4
#endif

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer */
struct ixgbe_tx_buffer {
	union ixgbe_adv_tx_desc *next_to_watch;
	unsigned long time_stamp;
	dma_addr_t dma;
	u32 length;
	u32 tx_flags;
	struct sk_buff *skb;
	u32 bytecount;
	u16 gso_segs;
};

struct ixgbe_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
	dma_addr_t page_dma;
	unsigned int page_offset;
};

struct ixgbe_queue_stats {
	u64 packets;
	u64 bytes;
};

struct ixgbe_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 completed;
	u64 tx_done_old;
};

struct ixgbe_rx_queue_stats {
	u64 rsc_count;
	u64 rsc_flush;
	u64 non_eop_descs;
	u64 alloc_rx_page_failed;
	u64 alloc_rx_buff_failed;
};

enum ixbge_ring_state_t {
	__IXGBE_TX_FDIR_INIT_DONE,
	__IXGBE_TX_DETECT_HANG,
	__IXGBE_HANG_CHECK_ARMED,
	__IXGBE_RX_PS_ENABLED,
	__IXGBE_RX_RSC_ENABLED,
#ifndef IXGBE_NO_LRO
	__IXGBE_RX_LRO_ENABLED,
#endif
};

#define ring_is_ps_enabled(ring) \
	test_bit(__IXGBE_RX_PS_ENABLED, &(ring)->state)
#define set_ring_ps_enabled(ring) \
	set_bit(__IXGBE_RX_PS_ENABLED, &(ring)->state)
#define clear_ring_ps_enabled(ring) \
	clear_bit(__IXGBE_RX_PS_ENABLED, &(ring)->state)
#define check_for_tx_hang(ring) \
	test_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#define set_check_for_tx_hang(ring) \
	set_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#define clear_check_for_tx_hang(ring) \
	clear_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#ifndef IXGBE_NO_HW_RSC
#define ring_is_rsc_enabled(ring) \
	test_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#else
#define ring_is_rsc_enabled(ring) false
#endif
#define set_ring_rsc_enabled(ring) \
	set_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#define clear_ring_rsc_enabled(ring) \
	clear_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#ifndef IXGBE_NO_LRO
#define ring_is_lro_enabled(ring) \
	test_bit(__IXGBE_RX_LRO_ENABLED, &(ring)->state)
#define set_ring_lro_enabled(ring) \
	set_bit(__IXGBE_RX_LRO_ENABLED, &(ring)->state)
#define clear_ring_lro_enabled(ring) \
	clear_bit(__IXGBE_RX_LRO_ENABLED, &(ring)->state)
#endif /* IXGBE_NO_LRO */
struct ixgbe_ring {
	struct ixgbe_ring *next;	/* pointer to next ring in q_vector */
	void *desc;			/* descriptor ring memory */
	struct device *dev;             /* device for dma mapping */
	struct net_device *netdev;      /* netdev ring belongs to */
	union {
		struct ixgbe_tx_buffer *tx_buffer_info;
		struct ixgbe_rx_buffer *rx_buffer_info;
	};
	unsigned long state;
	u8 __iomem *tail;

	u16 count;			/* amount of descriptors */
	u16 rx_buf_len;

	u8 queue_index; /* needed for multiqueue queue management */
	u8 reg_idx;			/* holds the special value that gets the
					 * hardware register offset associated
					 * with this ring, which is different
					 * for DCB and RSS modes */
	u8 atr_sample_rate;
	u8 atr_count;

	u16 next_to_use;
	u16 next_to_clean;

	struct ixgbe_queue_stats stats;
	union {
		struct ixgbe_tx_queue_stats tx_stats;
		struct ixgbe_rx_queue_stats rx_stats;
	};
	int numa_node;
	unsigned int size;		/* length in bytes */
	dma_addr_t dma;			/* phys. address of descriptor ring */
	struct ixgbe_q_vector *q_vector; /* backpointer to host q_vector */
} ____cacheline_internodealigned_in_smp;

enum ixgbe_ring_f_enum {
	RING_F_NONE = 0,
	RING_F_DCB,
	RING_F_VMDQ,
	RING_F_RSS,
	RING_F_FDIR,
#ifdef IXGBE_FCOE
	RING_F_FCOE,
#endif /* IXGBE_FCOE */
	RING_F_ARRAY_SIZE      /* must be last in enum set */
};

#define IXGBE_MAX_DCB_INDICES   8
#define IXGBE_MAX_RSS_INDICES  16
#define IXGBE_MAX_VMDQ_INDICES 64
#define IXGBE_MAX_FDIR_INDICES 64
#ifdef IXGBE_FCOE
#define IXGBE_MAX_FCOE_INDICES 8
#define MAX_RX_QUEUES (IXGBE_MAX_FDIR_INDICES + IXGBE_MAX_FCOE_INDICES)
#define MAX_TX_QUEUES (IXGBE_MAX_FDIR_INDICES + IXGBE_MAX_FCOE_INDICES)
#else
#define MAX_RX_QUEUES IXGBE_MAX_FDIR_INDICES
#define MAX_TX_QUEUES IXGBE_MAX_FDIR_INDICES
#endif /* IXGBE_FCOE */
struct ixgbe_ring_feature {
	int indices;
	int mask;
};


#define MAX_RX_PACKET_BUFFERS ((adapter->flags & IXGBE_FLAG_DCB_ENABLED) \
                               ? 8 : 1)
#define MAX_TX_PACKET_BUFFERS MAX_RX_PACKET_BUFFERS

/* MAX_MSIX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct ixgbe_q_vector {
	struct ixgbe_adapter *adapter;
	unsigned int v_idx; /* index of q_vector within array, also used for
	                     * finding the bit in EICR and friends that
	                     * represents the vector for this ring */
	int cpu;	    /* cpu for DCA */
#ifdef CONFIG_IXGBE_NAPI
	struct napi_struct napi;
#endif
	struct ixgbe_ring *rx_ring;
	struct ixgbe_ring *tx_ring;
	u8 rxr_count;     /* Rx ring count assigned to this vector */
	u8 txr_count;     /* Tx ring count assigned to this vector */

	u8 rx_itr;
	u8 tx_itr;

	u32 eitr;

	u16 rx_work_limit;                /* max RX work per interrupt */
	u16 tx_work_limit;                /* max TX work per interrupt */

	unsigned int total_rx_bytes;
	unsigned int total_rx_packets;

	unsigned int total_tx_bytes;
	unsigned int total_tx_packets;

	struct ixgbe_lro_list *lrolist;   /* LRO list for queue vector*/
	char name[IFNAMSIZ + 9];
#ifndef HAVE_NETDEV_NAPI_LIST
	struct net_device poll_dev;
#endif
#ifdef HAVE_IRQ_AFFINITY_HINT
	cpumask_var_t affinity_mask;
#endif
} ____cacheline_internodealigned_in_smp;


/* Helper macros to switch between ints/sec and what the register uses.
 * And yes, it's the same math going both ways.  The lowest value
 * supported by all of the ixgbe hardware is 8.
 */
#define EITR_INTS_PER_SEC_TO_REG(_eitr) \
	((_eitr) ? (1000000000 / ((_eitr) * 256)) : 8)
#define EITR_REG_TO_INTS_PER_SEC EITR_INTS_PER_SEC_TO_REG

#define IXGBE_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define IXGBE_RX_DESC_ADV(R, i)	    \
	(&(((union ixgbe_adv_rx_desc *)((R)->desc))[i]))
#define IXGBE_TX_DESC_ADV(R, i)	    \
	(&(((union ixgbe_adv_tx_desc *)((R)->desc))[i]))
#define IXGBE_TX_CTXTDESC_ADV(R, i)	    \
	(&(((struct ixgbe_adv_tx_context_desc *)((R)->desc))[i]))

#define IXGBE_MAX_JUMBO_FRAME_SIZE        16128
#ifdef IXGBE_FCOE
/* use 3K as the baby jumbo frame size for FCoE */
#define IXGBE_FCOE_JUMBO_FRAME_SIZE       3072
#endif /* IXGBE_FCOE */

#define TCP_TIMER_VECTOR 0
#define OTHER_VECTOR 1
#define NON_Q_VECTORS (OTHER_VECTOR + TCP_TIMER_VECTOR)

#define IXGBE_MAX_MSIX_VECTORS_82599 64
#define IXGBE_MAX_MSIX_Q_VECTORS_82599 64
#define IXGBE_MAX_MSIX_Q_VECTORS_82598 16
#define IXGBE_MAX_MSIX_VECTORS_82598 18

/*
 * Only for array allocations in our adapter struct.  On 82598, there will be
 * unused entries in the array, but that's not a big deal.  Also, in 82599,
 * we can actually assign 64 queue vectors based on our extended-extended
 * interrupt registers.  This is different than 82598, which is limited to 16.
 */
#define MAX_MSIX_Q_VECTORS IXGBE_MAX_MSIX_Q_VECTORS_82599
#define MAX_MSIX_COUNT IXGBE_MAX_MSIX_VECTORS_82599

#define MIN_MSIX_Q_VECTORS 1 
#define MIN_MSIX_COUNT (MIN_MSIX_Q_VECTORS + NON_Q_VECTORS)

/* board specific private data structure */
struct ixgbe_adapter {
	struct timer_list service_timer;
#ifdef NETIF_F_HW_VLAN_TX
	struct vlan_group *vlgrp;
#endif
	u16 bd_number;
	struct ixgbe_q_vector *q_vector[MAX_MSIX_Q_VECTORS];
	struct ixgbe_dcb_config dcb_cfg;
	struct ixgbe_dcb_config temp_dcb_cfg;
	u8 dcb_set_bitmap;
	enum ixgbe_fc_mode last_lfc_mode;

	/* Interrupt Throttle Rate */
	u32 rx_itr_setting;
	u32 tx_itr_setting;

	/* Work limits */
	u16 rx_work_limit;
	u16 tx_work_limit;

	/* TX */
	struct ixgbe_ring *tx_ring[MAX_TX_QUEUES] ____cacheline_aligned_in_smp;
	int num_tx_queues;
	u32 tx_timeout_count;

	u64 restart_queue;
	u64 lsc_int;

	/* RX */
	struct ixgbe_ring *rx_ring[MAX_TX_QUEUES] ____cacheline_aligned_in_smp;
	int num_rx_queues;
	int num_rx_pools;               /* == num_rx_queues in 82598 */
	int num_rx_queues_per_pool;	/* 1 if 82598, can be many if 82599 */
	u64 hw_csum_rx_error;
	u64 hw_rx_no_dma_resources;
	u64 non_eop_descs;
#ifndef CONFIG_IXGBE_NAPI
	u64 rx_dropped_backlog;		/* count drops from rx intr handler */
#endif
	int num_msix_vectors;
	int max_msix_q_vectors;         /* true count of q_vectors for device */
	struct ixgbe_ring_feature ring_feature[RING_F_ARRAY_SIZE];
	struct msix_entry *msix_entries;

	u32 alloc_rx_page_failed;
	u32 alloc_rx_buff_failed;

	/* Some features need tri-state capability,
	 * thus the additional *_CAPABLE flags.
	 */
	u32 flags;
#define IXGBE_FLAG_RX_CSUM_ENABLED              (u32)(1)
#define IXGBE_FLAG_MSI_CAPABLE                  (u32)(1 << 1)
#define IXGBE_FLAG_MSI_ENABLED                  (u32)(1 << 2)
#define IXGBE_FLAG_MSIX_CAPABLE                 (u32)(1 << 3)
#define IXGBE_FLAG_MSIX_ENABLED                 (u32)(1 << 4)
#ifndef IXGBE_NO_LLI
#define IXGBE_FLAG_LLI_PUSH                     (u32)(1 << 5)
#endif
#define IXGBE_FLAG_RX_1BUF_CAPABLE              (u32)(1 << 6)
#define IXGBE_FLAG_RX_PS_CAPABLE                (u32)(1 << 7)
#define IXGBE_FLAG_RX_PS_ENABLED                (u32)(1 << 8)
#define IXGBE_FLAG_IN_NETPOLL                   (u32)(1 << 9)
#define IXGBE_FLAG_DCA_ENABLED                  (u32)(1 << 10)
#define IXGBE_FLAG_DCA_CAPABLE                  (u32)(1 << 11)
#define IXGBE_FLAG_DCA_ENABLED_DATA             (u32)(1 << 12)
#define IXGBE_FLAG_MQ_CAPABLE                   (u32)(1 << 13)
#define IXGBE_FLAG_DCB_ENABLED                  (u32)(1 << 14)
#define IXGBE_FLAG_DCB_CAPABLE                  (u32)(1 << 15)
#define IXGBE_FLAG_RSS_ENABLED                  (u32)(1 << 16)
#define IXGBE_FLAG_RSS_CAPABLE                  (u32)(1 << 17)
#define IXGBE_FLAG_VMDQ_CAPABLE                 (u32)(1 << 18)
#define IXGBE_FLAG_VMDQ_ENABLED                 (u32)(1 << 19)
#define IXGBE_FLAG_FAN_FAIL_CAPABLE             (u32)(1 << 20)
#define IXGBE_FLAG_NEED_LINK_UPDATE             (u32)(1 << 22)
#define IXGBE_FLAG_NEED_LINK_CONFIG             (u32)(1 << 24)
#define IXGBE_FLAG_FDIR_HASH_CAPABLE            (u32)(1 << 26)
#define IXGBE_FLAG_FDIR_PERFECT_CAPABLE         (u32)(1 << 27)
#ifdef IXGBE_FCOE
#define IXGBE_FLAG_FCOE_CAPABLE                 (u32)(1 << 28)
#define IXGBE_FLAG_FCOE_ENABLED                 (u32)(1 << 29)
#endif /* IXGBE_FCOE */
#define IXGBE_FLAG_SRIOV_CAPABLE                (u32)(1 << 30)
#define IXGBE_FLAG_SRIOV_ENABLED                (u32)(1 << 31)

	u32 flags2;
#ifndef IXGBE_NO_HW_RSC
#define IXGBE_FLAG2_RSC_CAPABLE                  (u32)(1)
#define IXGBE_FLAG2_RSC_ENABLED                  (u32)(1 << 1)
#else
#define IXGBE_FLAG2_RSC_CAPABLE                  0
#define IXGBE_FLAG2_RSC_ENABLED                  0
#endif
#define IXGBE_FLAG2_SWLRO_ENABLED                (u32)(1 << 2)
#define IXGBE_FLAG2_VMDQ_DEFAULT_OVERRIDE        (u32)(1 << 3)
#define IXGBE_FLAG2_TEMP_SENSOR_CAPABLE          (u32)(1 << 5)
#define IXGBE_FLAG2_TEMP_SENSOR_EVENT            (u32)(1 << 6)
#define IXGBE_FLAG2_SEARCH_FOR_SFP               (u32)(1 << 7)
#define IXGBE_FLAG2_SFP_NEEDS_RESET              (u32)(1 << 8)
#define IXGBE_FLAG2_RESET_REQUESTED              (u32)(1 << 9)
#define IXGBE_FLAG2_FDIR_REQUIRES_REINIT         (u32)(1 << 10)

/* default to trying for four seconds */
#define IXGBE_TRY_LINK_TIMEOUT (4 * HZ)

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;
#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats net_stats;
#endif
#ifndef IXGBE_NO_LRO
	struct ixgbe_lro_stats lro_stats;
#endif

#ifdef ETHTOOL_TEST
	u32 test_icr;
	struct ixgbe_ring test_tx_ring;
	struct ixgbe_ring test_rx_ring;
#endif

	/* structs defined in ixgbe_hw.h */
	struct ixgbe_hw hw;
	u16 msg_enable;
	struct ixgbe_hw_stats stats;
#ifndef IXGBE_NO_LLI
	u32 lli_port;
	u32 lli_size;
	u64 lli_int;
	u32 lli_etype;
	u32 lli_vlan_pri;
#endif /* IXGBE_NO_LLI */
	/* Interrupt Throttle Rate */
	u32 rx_eitr_param;
	u32 tx_eitr_param;

	unsigned long state;
	u32 *config_space;
	u64 tx_busy;
	unsigned int tx_ring_count;
	unsigned int rx_ring_count;

	u32 link_speed;
	bool link_up;
	unsigned long link_check_timeout;

	struct work_struct service_task;
	u64 flm;
	u32 fdir_pballoc;
	u32 atr_sample_rate;
	spinlock_t fdir_perfect_lock;
#ifdef IXGBE_FCOE
	struct ixgbe_fcoe fcoe;
#endif /* IXGBE_FCOE */
	u64 rsc_total_count;
	u64 rsc_total_flush;
	u32 wol;
	u16 eeprom_version;
	bool netdev_registered;
	char lsc_int_name[IFNAMSIZ + 9];
	u32 interrupt_event;

	DECLARE_BITMAP(active_vfs, IXGBE_MAX_VF_FUNCTIONS);
	unsigned int num_vfs;
	bool repl_enable;
	bool l2switch_enable;
	struct vf_data_storage *vfinfo;
	int node;
	unsigned long fdir_overflow; /* number of times ATR was backed off */
};


enum ixbge_state_t {
	__IXGBE_TESTING,
	__IXGBE_RESETTING,
	__IXGBE_DOWN,
	__IXGBE_SERVICE_SCHED,
	__IXGBE_IN_SFP_INIT,
};

struct ixgbe_rsc_cb {
	struct sk_buff *head;
	dma_addr_t dma;
	u16 append_cnt;
	bool delay_unmap;
};
#define IXGBE_RSC_CB(skb) ((struct ixgbe_rsc_cb *)(skb)->cb)

extern struct dcbnl_rtnl_ops dcbnl_ops;
extern int ixgbe_copy_dcb_cfg(struct ixgbe_dcb_config *src_dcb_cfg,
			      struct ixgbe_dcb_config *dst_dcb_cfg, int tc_max);

extern u8 ixgbe_dcb_txq_to_tc(struct ixgbe_adapter *adapter, u8 index);

/* needed by ixgbe_main.c */
extern int ixgbe_validate_mac_addr(u8 *mc_addr);
extern void ixgbe_check_options(struct ixgbe_adapter *adapter);
extern void ixgbe_assign_netdev_ops(struct net_device *netdev);

/* needed by ixgbe_ethtool.c */
extern char ixgbe_driver_name[];
extern const char ixgbe_driver_version[];

extern int ixgbe_up(struct ixgbe_adapter *adapter);
extern void ixgbe_down(struct ixgbe_adapter *adapter);
extern void ixgbe_reinit_locked(struct ixgbe_adapter *adapter);
extern void ixgbe_reset(struct ixgbe_adapter *adapter);
extern void ixgbe_set_ethtool_ops(struct net_device *netdev);
extern int ixgbe_setup_rx_resources(struct ixgbe_ring *);
extern int ixgbe_setup_tx_resources(struct ixgbe_ring *);
extern void ixgbe_free_rx_resources(struct ixgbe_ring *);
extern void ixgbe_free_tx_resources(struct ixgbe_ring *);
extern void ixgbe_configure_rx_ring(struct ixgbe_adapter *,struct ixgbe_ring *);
extern void ixgbe_configure_tx_ring(struct ixgbe_adapter *,struct ixgbe_ring *);
extern void ixgbe_update_stats(struct ixgbe_adapter *adapter);
extern int ixgbe_init_interrupt_scheme(struct ixgbe_adapter *adapter);
extern void ixgbe_clear_interrupt_scheme(struct ixgbe_adapter *adapter);
extern bool ixgbe_is_ixgbe(struct pci_dev *pcidev);
extern netdev_tx_t ixgbe_xmit_frame_ring(struct sk_buff *,
					 struct ixgbe_adapter *,
					 struct ixgbe_ring *);
extern void ixgbe_unmap_and_free_tx_resource(struct ixgbe_ring *,
                                             struct ixgbe_tx_buffer *);
extern void ixgbe_alloc_rx_buffers(struct ixgbe_ring *, u16);
extern void ixgbe_configure_rscctl(struct ixgbe_adapter *adapter, struct ixgbe_ring *);
extern void ixgbe_clear_rscctl(struct ixgbe_adapter *adapter, struct ixgbe_ring *);
extern void ixgbe_set_rx_mode(struct net_device *netdev);
extern void ixgbe_tx_ctxtdesc(struct ixgbe_ring *, u32, u32, u32, u32);
extern void ixgbe_write_eitr(struct ixgbe_q_vector *q_vector);
extern void ixgbe_disable_rx_queue(struct ixgbe_adapter *adapter,
				   struct ixgbe_ring *);
#ifdef ETHTOOL_OPS_COMPAT
extern int ethtool_ioctl(struct ifreq *ifr);
#endif
extern int ixgbe_dcb_netlink_register(void);
extern int ixgbe_dcb_netlink_unregister(void);


#ifdef IXGBE_FCOE
extern void ixgbe_configure_fcoe(struct ixgbe_adapter *adapter);
extern int ixgbe_fso(struct ixgbe_ring *tx_ring, struct sk_buff *skb,
                     u32 tx_flags, u8 *hdr_len);
extern void ixgbe_cleanup_fcoe(struct ixgbe_adapter *adapter);
extern int ixgbe_fcoe_ddp(struct ixgbe_adapter *adapter,
                          union ixgbe_adv_rx_desc *rx_desc,
                          struct sk_buff *skb,
			  u32 staterr);
extern int ixgbe_fcoe_ddp_get(struct net_device *netdev, u16 xid,
                              struct scatterlist *sgl, unsigned int sgc);
extern int ixgbe_fcoe_ddp_put(struct net_device *netdev, u16 xid);
#ifdef HAVE_NETDEV_OPS_FCOE_ENABLE
extern int ixgbe_fcoe_enable(struct net_device *netdev);
extern int ixgbe_fcoe_disable(struct net_device *netdev);
#endif /* HAVE_NETDEV_OPS_FCOE_ENABLE */
#ifdef CONFIG_DCB
#ifdef HAVE_DCBNL_OPS_GETAPP
extern u8 ixgbe_fcoe_getapp(struct ixgbe_adapter *adapter);
extern u8 ixgbe_fcoe_setapp(struct ixgbe_adapter *adapter, u8 up);
#endif /* HAVE_DCBNL_OPS_GETAPP */
#endif /* CONFIG_DCB */
#ifdef HAVE_NETDEV_OPS_FCOE_GETWWN
extern int ixgbe_fcoe_get_wwn(struct net_device *netdev, u64 *wwn, int type);
#endif
#endif /* IXGBE_FCOE */


#endif /* _IXGBE_H_ */
