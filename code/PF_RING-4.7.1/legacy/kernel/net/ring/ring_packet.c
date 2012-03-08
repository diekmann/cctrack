/* ***************************************************************
 *
 * (C) 2004-09 - Luca Deri <deri@ntop.org>
 *
 * This code includes contributions courtesy of
 * - Amit D. Chaudhary <amit_ml@rajgad.com>
 * - Andrew Gallatin <gallatyn@myri.com>
 * - Brad Doctor <brad@stillsecure.com>
 * - Felipe Huici <felipe.huici@nw.neclab.eu>
 * - Francesco Fusco <fusco@ntop.org> (IP defrag)
 * - Helmut Manck <helmut.manck@secunet.com>
 * - Hitoshi Irino <irino@sfc.wide.ad.jp>
 * - Jakov Haron <jyh@cabel.net>
 * - Jeff Randall <jrandall@nexvu.com>
 * - Kevin Wormington <kworm@sofnet.com>
 * - Mahdi Dashtbozorgi <rdfm2000@gmail.com>
 * - Marketakis Yannis <marketak@ics.forth.gr>
 * - Matthew J. Roth <mroth@imminc.com>
 * - Michael Stiller <ms@2scale.net> (VM memory support)
 * - Noam Dev <noamdev@gmail.com>
 * - Siva Kollipara <siva@cs.arizona.edu>
 * - Vincent Carrier <vicarrier@wanadoo.fr>
 * - Eugene Bogush <b_eugene@ukr.net>
 * - Samir Chang <coobyhb@gmail.com>
 * - Ury Stankevich <urykhy@gmail.com>
 * - Raja Mukerji <raja@mukerji.com>
 * - Davide Viti <zinosat@tiscali.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
#include <linux/version.h>
#include <linux/autoconf.h>
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
#include <linux/ring.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>		/* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>
/* #define RING_DEBUG */
/* ************************************************* */
#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20
/* ************************************************* */
#define PROC_INFO         "info"
#define PROC_PLUGINS_INFO "plugins_info"
/* ************************************************* */
/* List of all ring sockets. */
static struct list_head ring_table;
static u_int ring_table_size;

/*
  For each device, pf_ring keeps a list of the number of
  available ring socket slots. So that a caller knows in advance whether
  there are slots available (for rings bound to such device)
  that can potentially host the packet
*/
static struct list_head device_ring_list[MAX_NUM_DEVICES];

/* List of all clusters */
static struct list_head ring_cluster_list;

/* List of all dna (direct nic access) devices */
static struct list_head ring_dna_devices_list;
static u_int dna_devices_list_size = 0;

/* List of all plugins */
static u_int plugin_registration_size = 0;
static struct pfring_plugin_registration *plugin_registration[MAX_PLUGIN_ID] =
{ NULL };
static u_short max_registered_plugin_id = 0;
static rwlock_t ring_mgmt_lock = RW_LOCK_UNLOCKED;
static rwlock_t ring_list_lock = RW_LOCK_UNLOCKED;

/* ********************************** */

/* /proc entry for ring module */
struct proc_dir_entry *ring_proc_dir = NULL;
struct proc_dir_entry *ring_proc = NULL;
struct proc_dir_entry *ring_proc_plugins_info = NULL;

static int ring_proc_get_info(char *, char **, off_t, int, int *, void *);
static int ring_proc_get_plugin_info(char *, char **, off_t, int, int *,
				     void *);
static void ring_proc_add(struct ring_opt *pfr, struct net_device *dev);
static void ring_proc_remove(struct ring_opt *pfr);
static void ring_proc_init(void);
static void ring_proc_term(void);

/*
  Caveat
  [http://lists.metaprl.org/pipermail/cs134-labs/2002-October/000025.html]

  GFP_ATOMIC means roughly "make the allocation operation atomic".  This
  means that the kernel will try to find the memory using a pile of free
  memory set aside for urgent allocation.  If that pile doesn't have
  enough free pages, the operation will fail.  This flag is useful for
  allocation within interrupt handlers.

  GFP_KERNEL will try a little harder to find memory.  There's a
  possibility that the call to kmalloc() will sleep while the kernel is
  trying to find memory (thus making it unsuitable for interrupt
  handlers).  It's much more rare for an allocation with GFP_KERNEL to
  fail than with GFP_ATOMIC.

  In all cases, kmalloc() should only be used allocating small amounts of
  memory (a few kb).  vmalloc() is better for larger amounts.

  Also note that in lab 1 and lab 2, it would have been arguably better to
  use GFP_KERNEL instead of GFP_ATOMIC.  GFP_ATOMIC should be saved for
  those instances in which a sleep would be totally unacceptable.
*/
/* ********************************** */

/* Forward */
static struct proto_ops ring_ops;
static struct proto ring_proto;

static int skb_ring_handler(struct sk_buff *skb, u_char recv_packet,
			    u_char real_skb, short channel_id);
static int buffer_ring_handler(struct net_device *dev, char *data, int len);
static int remove_from_cluster(struct sock *sock, struct ring_opt *pfr);

/* Extern */
extern int ip_defrag(struct sk_buff *skb, u32 user);

/* ********************************** */

/* Defaults */
static unsigned int num_slots = 4096;
static unsigned int enable_tx_capture = 1;
static unsigned int enable_ip_defrag = 0;
static unsigned int transparent_mode = 1;
static u_int32_t ring_id_serial = 0;

module_param(num_slots, uint, 0644);
module_param(transparent_mode, uint, 0644);
module_param(enable_tx_capture, uint, 0644);
module_param(enable_ip_defrag, uint, 0644);

MODULE_PARM_DESC(num_slots, "Number of ring slots");
MODULE_PARM_DESC(transparent_mode,
		 "Set to 1 to set transparent mode "
		 "(slower but backwards compatible)");
MODULE_PARM_DESC(enable_tx_capture, "Set to 1 to capture outgoing packets");
MODULE_PARM_DESC(enable_ip_defrag,
		 "Set to 1 to enable IP defragmentation"
		 "(only rx traffic is defragmentead)");

/* ********************************** */

#define MIN_QUEUED_PKTS      64
#define MAX_QUEUE_LOOPS      64

#define ring_sk_datatype(__sk) ((struct ring_opt *)__sk)
#define ring_sk(__sk) ((__sk)->sk_protinfo)

#define _rdtsc() ({ uint64_t x; asm volatile("rdtsc" : "=A" (x)); x; })

/* ***** Code taken from other kernel modules ******** */

/**
 * rvmalloc copied from usbvideo.c
 */
static void *rvmalloc(unsigned long size)
{
	void *mem;
	unsigned long adr;
	unsigned long pages = 0;

#if defined(RING_DEBUG)
	printk("[PF_RING] rvmalloc: %lu bytes\n", size);
#endif

	size = PAGE_ALIGN(size);
	mem = vmalloc_32(size);
	if (!mem)
		return NULL;

	memset(mem, 0, size);	/* Clear the ram out, no junk to the user */
	adr = (unsigned long)mem;
	while (size > 0) {
		SetPageReserved(vmalloc_to_page((void *)adr));
		pages++;
		adr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

#if defined(RING_DEBUG)
	printk("[PF_RING] rvmalloc: %lu pages\n", pages);
#endif
	return mem;
}

/* ************************************************** */

/**
 * rvfree copied from usbvideo.c
 */
static void rvfree(void *mem, unsigned long size)
{
	unsigned long adr;
	unsigned long pages = 0;

#if defined(RING_DEBUG)
	printk("[PF_RING] rvfree: %lu bytes\n", size);
#endif

	if (!mem)
		return;

	adr = (unsigned long)mem;
	while ((long)size > 0) {
		ClearPageReserved(vmalloc_to_page((void *)adr));
		pages++;
		adr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
#if defined(RING_DEBUG)
	printk("[PF_RING] rvfree: %lu pages\n", pages);
	printk("[PF_RING] rvfree: calling vfree....\n");
#endif
	vfree(mem);
#if defined(RING_DEBUG)
	printk("[PF_RING] rvfree: after vfree....\n");
#endif
}

/* ********************************** */

#define IP_DEFRAG_RING 1234

/* Returns new sk_buff, or NULL  */
static struct sk_buff *ring_gather_frags(struct sk_buff *skb)
{
	if (ip_defrag(skb, IP_DEFRAG_RING))
		skb = NULL;
	else
		ip_send_check(ip_hdr(skb));

	return (skb);
}

/* ********************************** */

static void ring_sock_destruct(struct sock *sk)
{
	struct ring_opt *pfr;

	skb_queue_purge(&sk->sk_receive_queue);

	if (!sock_flag(sk, SOCK_DEAD)) {
#if defined(RING_DEBUG)
		printk("[PF_RING] Attempt to release alive ring socket: %p\n",
		       sk);
#endif
		return;
	}

	pfr = ring_sk(sk);

	if (pfr)
		kfree(pfr);
}

/* ********************************** */

static void ring_proc_add(struct ring_opt *pfr, struct net_device *dev)
{
	if (ring_proc_dir != NULL) {
		char name[64];

		pfr->ring_pid = current->pid;
		pfr->ring_id = ring_id_serial++;

		if (NULL != dev)
			snprintf(name, sizeof(name), "%d-%s.%d", pfr->ring_pid,
				 dev->name, pfr->ring_id);
		else
			snprintf(name, sizeof(name), "%d.%d", pfr->ring_pid,
				 pfr->ring_id);

		create_proc_read_entry(name, 0, ring_proc_dir,
				       ring_proc_get_info, pfr);
		/* printk("[PF_RING] added /proc/net/pf_ring/%s\n", name); */
		/* printk("[PF_RING] %s has index %d\n", dev->name, dev->ifindex); */
	}
}

/* ********************************** */

static void ring_proc_remove(struct ring_opt *pfr)
{
	if (ring_proc_dir != NULL) {
		char name[64];

		if (pfr->ring_netdev && pfr->ring_netdev->name)
			snprintf(name, sizeof(name), "%d-%s.%d",
				 pfr->ring_pid, pfr->ring_netdev->name,
				 pfr->ring_id);
		else
			snprintf(name, sizeof(name), "%d.%d", pfr->ring_pid,
				 pfr->ring_id);

		remove_proc_entry(name, ring_proc_dir);
		printk("[PF_RING] removed /proc/net/pf_ring/%s\n", name);
	}
}

/* ********************************** */

static u_int32_t num_queued_pkts(struct ring_opt *pfr)
{
	if (pfr->ring_slots != NULL) {
		u_int32_t tot_insert = pfr->slots_info->tot_insert, tot_read =
			pfr->slots_info->tot_read;

		if (tot_insert >= tot_read) {
			return (tot_insert - tot_read);
		} else {
			return (((u_int32_t) - 1) + tot_insert - tot_read);
		}

#if defined(RING_DEBUG)
		printk("[PF_RING] -> [tot_insert=%d][tot_read=%d]\n",
		       tot_insert, tot_read);
#endif
	} else
		return (0);
}

/* ************************************* */

inline u_int get_num_ring_free_slots(struct ring_opt * pfr)
{
	return (pfr->slots_info->tot_slots - num_queued_pkts(pfr));
}

/* ********************************** */

static int ring_proc_get_info(char *buf, char **start, off_t offset,
			      int len, int *unused, void *data)
{
	int rlen = 0;
	struct ring_opt *pfr;
	FlowSlotInfo *fsi;

	if (data == NULL) {
		/* /proc/net/pf_ring/info */
		rlen = sprintf(buf, "PF_RING Version     : %s\n", RING_VERSION);
		rlen +=
			sprintf(buf + rlen, "Ring slots          : %d\n",
				num_slots);
		rlen +=
			sprintf(buf + rlen, "Slot version        : %d\n",
				RING_FLOWSLOT_VERSION);
		rlen +=
			sprintf(buf + rlen, "Capture TX          : %s\n",
				enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
		rlen +=
			sprintf(buf + rlen, "IP Defragment       : %s\n",
				enable_ip_defrag ? "Yes" : "No");
		rlen +=
			sprintf(buf + rlen, "Transparent mode    : %s\n",
				transparent_mode ? "Yes" : "No");
		rlen +=
			sprintf(buf + rlen, "Total rings         : %d\n",
				ring_table_size);
		rlen +=
			sprintf(buf + rlen, "Total plugins       : %d\n",
				plugin_registration_size);
	} else {
		/* detailed statistics about a PF_RING */
		pfr = (struct ring_opt *)data;

		if (data) {
			fsi = pfr->slots_info;

			if (fsi) {
				rlen = sprintf(buf, "Bound Device   : %s\n",
					       pfr->ring_netdev->name ==
					       NULL ? "<NULL>" : pfr->
					       ring_netdev->name);
				rlen +=
					sprintf(buf + rlen,
						"Slot Version   : %d [%s]\n",
						fsi->version, RING_VERSION);
				rlen +=
					sprintf(buf + rlen, "Sampling Rate  : %d\n",
						pfr->sample_rate);
				rlen +=
					sprintf(buf + rlen, "Appl. Name     : %s\n",
						pfr->appl_name ? pfr->
						appl_name : "<unknown>");
				rlen +=
					sprintf(buf + rlen, "IP Defragment  : %s\n",
						enable_ip_defrag ? "Yes" : "No");
				rlen +=
					sprintf(buf + rlen, "BPF Filtering  : %s\n",
						pfr->
						bpfFilter ? "Enabled" : "Disabled");
				rlen +=
					sprintf(buf + rlen, "# Filt. Rules  : %d\n",
						pfr->num_filtering_rules);
				rlen +=
					sprintf(buf + rlen, "Cluster Id     : %d\n",
						pfr->cluster_id);
				rlen +=
					sprintf(buf + rlen, "Channel Id     : %d\n",
						pfr->channel_id);
				rlen +=
					sprintf(buf + rlen, "Tot Slots      : %d\n",
						fsi->tot_slots);
				rlen +=
					sprintf(buf + rlen, "Bucket Len     : %d\n",
						fsi->data_len);
				rlen +=
					sprintf(buf + rlen,
						"Slot Len       : %d [bucket+header]\n",
						fsi->slot_len);
				rlen +=
					sprintf(buf + rlen, "Tot Memory     : %d\n",
						fsi->tot_mem);
				rlen +=
					sprintf(buf + rlen,
						"Tot Packets    : %lu\n",
						(unsigned long)fsi->tot_pkts);
				rlen +=
					sprintf(buf + rlen,
						"Tot Pkt Lost   : %lu\n",
						(unsigned long)fsi->tot_lost);
				rlen +=
					sprintf(buf + rlen,
						"Tot Insert     : %lu\n",
						(unsigned long)fsi->tot_insert);
				rlen +=
					sprintf(buf + rlen,
						"Tot Read       : %lu\n",
						(unsigned long)fsi->tot_read);
				rlen +=
					sprintf(buf + rlen,
						"Tot Fwd Ok     : %lu\n",
						(unsigned long)fsi->tot_fwd_ok);
				rlen +=
					sprintf(buf + rlen,
						"Tot Fwd Errors : %lu\n",
						(unsigned long)fsi->tot_fwd_notok);
				rlen +=
					sprintf(buf + rlen, "Num Free Slots : %u\n",
						get_num_ring_free_slots(pfr));
			} else
				rlen = sprintf(buf, "WARNING fsi == NULL\n");
		} else
			rlen = sprintf(buf, "WARNING data == NULL\n");
	}

	return rlen;
}

/* ********************************** */

static int ring_proc_get_plugin_info(char *buf, char **start, off_t offset,
				     int len, int *unused, void *data)
{
	int rlen = 0, i = 0;
	struct pfring_plugin_registration *tmp = NULL;

	/* FIXME: I should now the number of plugins registered */
	if (!plugin_registration_size)
		return rlen;

	/* plugins_info */

	rlen += sprintf(buf + rlen, "ID\tPlugin\n");

	for (i = 0; i < MAX_PLUGIN_ID; i++) {
		tmp = plugin_registration[i];
		if (tmp) {
			rlen += sprintf(buf + rlen, "%d\t%s [%s]\n",
					tmp->plugin_id, tmp->name,
					tmp->description);
		}
	}

	return rlen;
}

/* ********************************** */

static void ring_proc_init(void)
{
	ring_proc_dir = proc_mkdir("pf_ring",
				   init_net.proc_net);

	if (ring_proc_dir) {
		ring_proc = create_proc_read_entry(PROC_INFO, 0,
						   ring_proc_dir,
						   ring_proc_get_info, NULL);
		ring_proc_plugins_info =
			create_proc_read_entry(PROC_PLUGINS_INFO, 0, ring_proc_dir,
					       ring_proc_get_plugin_info, NULL);
		if (!ring_proc || !ring_proc_plugins_info)
			printk("[PF_RING] unable to register proc file\n");
		else {
			printk("[PF_RING] registered /proc/net/pf_ring/\n");
		}
	} else
		printk("[PF_RING] unable to create /proc/net/pf_ring\n");
}

/* ********************************** */

static void ring_proc_term(void)
{
	if (ring_proc != NULL) {
		remove_proc_entry(PROC_INFO, ring_proc_dir);
		printk("[PF_RING] removed /proc/net/pf_ring/%s\n", PROC_INFO);

		remove_proc_entry(PROC_PLUGINS_INFO, ring_proc_dir);
		printk("[PF_RING] removed /proc/net/pf_ring/%s\n",
		       PROC_PLUGINS_INFO);

		if (ring_proc_dir != NULL) {
			remove_proc_entry("pf_ring",
					  init_net.proc_net);
			printk("[PF_RING] deregistered /proc/net/pf_ring\n");
		}
	}
}

/* ********************************** */

/*
 * ring_insert()
 *
 * store the sk in a new element and add it
 * to the head of the list.
 */
static inline void ring_insert(struct sock *sk)
{
	struct ring_element *next;
	struct ring_opt *pfr;

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_insert()\n");
#endif

	next = kmalloc(sizeof(struct ring_element), GFP_ATOMIC);
	if (next != NULL) {
		next->sk = sk;
		write_lock_bh(&ring_mgmt_lock);
		list_add(&next->list, &ring_table);
		write_unlock_bh(&ring_mgmt_lock);
	} else {
		if (net_ratelimit())
			printk("[PF_RING] net_ratelimit() failure\n");
	}

	ring_table_size++;
	//ring_proc_add(ring_sk(sk));
	pfr = (struct ring_opt *)ring_sk(sk);
	pfr->ring_pid = current->pid;
}

/* ********************************** */

/*
 * ring_remove()
 *
 * For each of the elements in the list:
 *  - check if this is the element we want to delete
 *  - if it is, remove it from the list, and free it.
 *
 * stop when we find the one we're looking for (break),
 * or when we reach the end of the list.
 */
static inline void ring_remove(struct sock *sk)
{
	struct list_head *ptr, *tmp_ptr;
	struct ring_element *entry;

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_remove()\n");
#endif

	list_for_each_safe(ptr, tmp_ptr, &ring_table) {
		entry = list_entry(ptr, struct ring_element, list);

		if (entry->sk == sk) {
			list_del(ptr);
			kfree(entry);
			ring_table_size--;
			break;
		}
	}

#if defined(RING_DEBUG)
	printk("[PF_RING] leaving ring_remove()\n");
#endif
}

/* ********************************** */

static inline FlowSlot *get_insert_slot(struct ring_opt *pfr)
{
	if (pfr->ring_slots != NULL) {
		FlowSlot *slot =
			(FlowSlot *) & (pfr->
					ring_slots[pfr->slots_info->insert_idx *
						   pfr->slots_info->slot_len]);
#if defined(RING_DEBUG)
		printk
			("[PF_RING] get_insert_slot(%d): returned slot [slot_state=%d]\n",
			 pfr->slots_info->insert_idx, slot->slot_state);
#endif
		return (slot);
	} else {
#if defined(RING_DEBUG)
		printk("[PF_RING] get_insert_slot(%d): NULL slot\n",
		       pfr->slots_info->insert_idx);
#endif
		return (NULL);
	}
}

/* ********************************** */

static inline FlowSlot *get_remove_slot(struct ring_opt *pfr)
{
#if defined(RING_DEBUG)
	printk("[PF_RING] get_remove_slot(%d)\n", pfr->slots_info->remove_idx);
#endif

	if (pfr->ring_slots != NULL)
		return ((FlowSlot *) &
			(pfr->
			 ring_slots[pfr->slots_info->remove_idx *
				    pfr->slots_info->slot_len]));
	else
		return (NULL);
}

/* ******************************************************* */

static int parse_pkt(struct sk_buff *skb,
		     u_int16_t skb_displ, struct pfring_pkthdr *hdr)
{
	struct iphdr *ip;
	struct ethhdr *eh = (struct ethhdr *)(skb->data - skb_displ);
	u_int16_t displ;

	memset(&hdr->parsed_pkt, 0, sizeof(struct pkt_parsing_info));
	hdr->parsed_header_len = 9;

	hdr->parsed_pkt.eth_type = ntohs(eh->h_proto);
	hdr->parsed_pkt.pkt_detail.offset.eth_offset = -skb_displ;

	if (hdr->parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */ ) {
		hdr->parsed_pkt.pkt_detail.offset.vlan_offset =
			hdr->parsed_pkt.pkt_detail.offset.eth_offset +
			sizeof(struct ethhdr);
		hdr->parsed_pkt.vlan_id =
			(skb->
			 data[hdr->parsed_pkt.pkt_detail.offset.vlan_offset] & 15) *
			256 +
			skb->data[hdr->parsed_pkt.pkt_detail.offset.vlan_offset +
				  1];
		hdr->parsed_pkt.eth_type =
			(skb->
			 data[hdr->parsed_pkt.pkt_detail.offset.vlan_offset +
			      2]) * 256 +
			skb->data[hdr->parsed_pkt.pkt_detail.offset.vlan_offset +
				  3];
		displ = 4;
	} else {
		displ = 0;
		hdr->parsed_pkt.vlan_id = 0;	/* Any VLAN */
	}

	if (hdr->parsed_pkt.eth_type == 0x0800 /* IP */ ) {
		hdr->parsed_pkt.pkt_detail.offset.l3_offset =
			hdr->parsed_pkt.pkt_detail.offset.eth_offset + displ +
			sizeof(struct ethhdr);
		ip = (struct iphdr *)(skb->data +
				      hdr->parsed_pkt.pkt_detail.offset.
				      l3_offset);

		hdr->parsed_pkt.ipv4_src =
			ntohl(ip->saddr), hdr->parsed_pkt.ipv4_dst =
			ntohl(ip->daddr), hdr->parsed_pkt.l3_proto = ip->protocol;
		hdr->parsed_pkt.ipv4_tos = ip->tos;
		hdr->parsed_pkt.pkt_detail.offset.l4_offset =
			hdr->parsed_pkt.pkt_detail.offset.l3_offset + ip->ihl * 4;

		if ((ip->protocol == IPPROTO_TCP)
		    || (ip->protocol == IPPROTO_UDP)) {
			if (ip->protocol == IPPROTO_TCP) {
				struct tcphdr *tcp =
					(struct tcphdr *)(skb->data +
							  hdr->parsed_pkt.
							  pkt_detail.offset.
							  l4_offset);
				hdr->parsed_pkt.l4_src_port =
					ntohs(tcp->source),
					hdr->parsed_pkt.l4_dst_port =
					ntohs(tcp->dest);
				hdr->parsed_pkt.pkt_detail.offset.
					payload_offset =
					hdr->parsed_pkt.pkt_detail.offset.
					l4_offset + (tcp->doff * 4);
				hdr->parsed_pkt.tcp_flags =
					(tcp->fin * TH_FIN_MULTIPLIER) +
					(tcp->syn * TH_SYN_MULTIPLIER) +
					(tcp->rst * TH_RST_MULTIPLIER) +
					(tcp->psh * TH_PUSH_MULTIPLIER) +
					(tcp->ack * TH_ACK_MULTIPLIER) +
					(tcp->urg * TH_URG_MULTIPLIER);
			} else if (ip->protocol == IPPROTO_UDP) {
				struct udphdr *udp =
					(struct udphdr *)(skb->data +
							  hdr->parsed_pkt.
							  pkt_detail.offset.
							  l4_offset);
				hdr->parsed_pkt.l4_src_port =
					ntohs(udp->source),
					hdr->parsed_pkt.l4_dst_port =
					ntohs(udp->dest);
				hdr->parsed_pkt.pkt_detail.offset.
					payload_offset =
					hdr->parsed_pkt.pkt_detail.offset.
					l4_offset + sizeof(struct udphdr);
			} else
				hdr->parsed_pkt.pkt_detail.offset.
					payload_offset =
					hdr->parsed_pkt.pkt_detail.offset.l4_offset;
		} else
			hdr->parsed_pkt.l4_src_port =
				hdr->parsed_pkt.l4_dst_port = 0;

		hdr->parsed_pkt.pkt_detail.offset.eth_offset = skb_displ;

		return (1);	/* IP */
	}
	/* TODO: handle IPv6 */
	return (0);		/* No IP */
}

/* ********************************** */

inline u_int32_t hash_pkt(u_int16_t vlan_id, u_int8_t proto,
			  u_int32_t host_peer_a, u_int32_t host_peer_b,
			  u_int16_t port_peer_a, u_int16_t port_peer_b)
{
	return (vlan_id + proto + host_peer_a + host_peer_b + port_peer_a +
		port_peer_b);
}

/* ********************************** */

inline u_int32_t hash_pkt_header(struct pfring_pkthdr * hdr, u_char mask_src,
				 u_char mask_dst)
{
	return (hash_pkt(hdr->parsed_pkt.vlan_id,
			 hdr->parsed_pkt.l3_proto,
			 mask_src ? 0 : hdr->parsed_pkt.ipv4_src,
			 mask_dst ? 0 : hdr->parsed_pkt.ipv4_dst,
			 mask_src ? 0 : hdr->parsed_pkt.l4_src_port,
			 mask_dst ? 0 : hdr->parsed_pkt.l4_dst_port));
}

/* ********************************** */

static int hash_bucket_match(filtering_hash_bucket * hash_bucket,
			     struct pfring_pkthdr *hdr,
			     u_char mask_src, u_char mask_dst)
{
	if ((hash_bucket->rule.proto == hdr->parsed_pkt.l3_proto)
	    && (hash_bucket->rule.vlan_id == hdr->parsed_pkt.vlan_id)
	    &&
	    (((hash_bucket->rule.host_peer_a ==
	       (mask_src ? 0 : hdr->parsed_pkt.ipv4_src))
	      && (hash_bucket->rule.host_peer_b ==
		  (mask_dst ? 0 : hdr->parsed_pkt.ipv4_dst))
	      && (hash_bucket->rule.port_peer_a ==
		  (mask_src ? 0 : hdr->parsed_pkt.l4_src_port))
	      && (hash_bucket->rule.port_peer_b ==
		  (mask_dst ? 0 : hdr->parsed_pkt.l4_dst_port)))
	     ||
	     ((hash_bucket->rule.host_peer_a ==
	       (mask_dst ? 0 : hdr->parsed_pkt.ipv4_dst))
	      && (hash_bucket->rule.host_peer_b ==
		  (mask_src ? 0 : hdr->parsed_pkt.ipv4_src))
	      && (hash_bucket->rule.port_peer_a ==
		  (mask_dst ? 0 : hdr->parsed_pkt.l4_dst_port))
	      && (hash_bucket->rule.port_peer_b ==
		  (mask_src ? 0 : hdr->parsed_pkt.l4_src_port))))) {
		hash_bucket->rule.internals.jiffies_last_match = jiffies;
		return (1);
	} else
		return (0);
}

/* ********************************** */

inline int hash_bucket_match_rule(filtering_hash_bucket * hash_bucket,
				  hash_filtering_rule * rule)
{
	int debug = 0;

	if (debug)
		printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
		       "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
		       hash_bucket->rule.vlan_id, hash_bucket->rule.proto,
		       ((hash_bucket->rule.host_peer_a >> 24) & 0xff),
		       ((hash_bucket->rule.host_peer_a >> 16) & 0xff),
		       ((hash_bucket->rule.host_peer_a >> 8) & 0xff),
		       ((hash_bucket->rule.host_peer_a >> 0) & 0xff),
		       hash_bucket->rule.port_peer_a,
		       ((hash_bucket->rule.host_peer_b >> 24) & 0xff),
		       ((hash_bucket->rule.host_peer_b >> 16) & 0xff),
		       ((hash_bucket->rule.host_peer_b >> 8) & 0xff),
		       ((hash_bucket->rule.host_peer_b >> 0) & 0xff),
		       hash_bucket->rule.port_peer_b,
		       rule->vlan_id, rule->proto,
		       ((rule->host_peer_a >> 24) & 0xff),
		       ((rule->host_peer_a >> 16) & 0xff),
		       ((rule->host_peer_a >> 8) & 0xff),
		       ((rule->host_peer_a >> 0) & 0xff),
		       rule->port_peer_a,
		       ((rule->host_peer_b >> 24) & 0xff),
		       ((rule->host_peer_b >> 16) & 0xff),
		       ((rule->host_peer_b >> 8) & 0xff),
		       ((rule->host_peer_b >> 0) & 0xff), rule->port_peer_b);

	if ((hash_bucket->rule.proto == rule->proto)
	    && (hash_bucket->rule.vlan_id == rule->vlan_id)
	    && (((hash_bucket->rule.host_peer_a == rule->host_peer_a)
		 && (hash_bucket->rule.host_peer_b == rule->host_peer_b)
		 && (hash_bucket->rule.port_peer_a == rule->port_peer_a)
		 && (hash_bucket->rule.port_peer_b == rule->port_peer_b))
		|| ((hash_bucket->rule.host_peer_a == rule->host_peer_b)
		    && (hash_bucket->rule.host_peer_b == rule->host_peer_a)
		    && (hash_bucket->rule.port_peer_a == rule->port_peer_b)
		    && (hash_bucket->rule.port_peer_b == rule->port_peer_a)))) {
		hash_bucket->rule.internals.jiffies_last_match = jiffies;
		return (1);
	} else
		return (0);
}

/* ********************************** */

inline int hash_filtering_rule_match(hash_filtering_rule * a,
				     hash_filtering_rule * b)
{
	int debug = 0;

	if (debug)
		printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
		       "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
		       a->vlan_id, a->proto,
		       ((a->host_peer_a >> 24) & 0xff),
		       ((a->host_peer_a >> 16) & 0xff),
		       ((a->host_peer_a >> 8) & 0xff),
		       ((a->host_peer_a >> 0) & 0xff),
		       a->port_peer_a,
		       ((a->host_peer_b >> 24) & 0xff),
		       ((a->host_peer_b >> 16) & 0xff),
		       ((a->host_peer_b >> 8) & 0xff),
		       ((a->host_peer_b >> 0) & 0xff),
		       a->port_peer_b,
		       b->vlan_id, b->proto,
		       ((b->host_peer_a >> 24) & 0xff),
		       ((b->host_peer_a >> 16) & 0xff),
		       ((b->host_peer_a >> 8) & 0xff),
		       ((b->host_peer_a >> 0) & 0xff),
		       b->port_peer_a,
		       ((b->host_peer_b >> 24) & 0xff),
		       ((b->host_peer_b >> 16) & 0xff),
		       ((b->host_peer_b >> 8) & 0xff),
		       ((b->host_peer_b >> 0) & 0xff), b->port_peer_b);

	if ((a->proto == b->proto)
	    && (a->vlan_id == b->vlan_id)
	    && (((a->host_peer_a == b->host_peer_a)
		 && (a->host_peer_b == b->host_peer_b)
		 && (a->port_peer_a == b->port_peer_a)
		 && (a->port_peer_b == b->port_peer_b))
		|| ((a->host_peer_a == b->host_peer_b)
		    && (a->host_peer_b == b->host_peer_a)
		    && (a->port_peer_a == b->port_peer_b)
		    && (a->port_peer_b == b->port_peer_a)))) {
		return (1);
	} else
		return (0);
}

/* ********************************** */

/* 0 = no match, 1 = match */
static int match_filtering_rule(struct ring_opt *the_ring,
				filtering_rule_element * rule,
				struct pfring_pkthdr *hdr,
				struct sk_buff *skb,
				int displ,
				struct parse_buffer *parse_memory_buffer[],
				u_int8_t * free_parse_mem,
				u_int * last_matched_plugin,
				rule_action_behaviour * behaviour)
{
	int debug = 0;

	/* if (debug) printk("[PF_RING] match_filtering_rule()\n"); */

	*behaviour = forward_packet_and_stop_rule_evaluation;	/* Default */

	if ((rule->rule.core_fields.vlan_id > 0)
	    && (hdr->parsed_pkt.vlan_id != rule->rule.core_fields.vlan_id))
		return (0);

	if ((rule->rule.core_fields.proto > 0)
	    && (hdr->parsed_pkt.l3_proto != rule->rule.core_fields.proto))
		return (0);

	if (rule->rule.core_fields.host_low > 0) {
		if (((hdr->parsed_pkt.ipv4_src <
		      rule->rule.core_fields.host_low)
		     || (hdr->parsed_pkt.ipv4_src >
			 rule->rule.core_fields.host_high))
		    &&
		    ((hdr->parsed_pkt.ipv4_dst <
		      rule->rule.core_fields.host_low)
		     || (hdr->parsed_pkt.ipv4_dst >
			 rule->rule.core_fields.host_high)))
			return (0);
	}

	if ((rule->rule.core_fields.port_high > 0)
	    &&
	    (!((hdr->parsed_pkt.l4_src_port >= rule->rule.core_fields.port_low)
	       && (hdr->parsed_pkt.l4_src_port <=
		   rule->rule.core_fields.port_high)))
	    &&
	    (!((hdr->parsed_pkt.l4_dst_port >= rule->rule.core_fields.port_low)
	       && (hdr->parsed_pkt.l4_dst_port <=
		   rule->rule.core_fields.port_high))))
		return (0);

	if (rule->rule.balance_pool > 0) {
		u_int32_t balance_hash =
			hash_pkt_header(hdr, 0, 0) % rule->rule.balance_pool;
		if (balance_hash != rule->rule.balance_id)
			return (0);
	}

	if (rule->pattern[0] != NULL) {
		if (debug)
			printk("[PF_RING] pattern\n");

		if ((hdr->parsed_pkt.pkt_detail.offset.payload_offset > 0)
		    && (hdr->caplen >
			hdr->parsed_pkt.pkt_detail.offset.payload_offset)) {
			char *payload =
				(char *)&(skb->
					  data[hdr->parsed_pkt.pkt_detail.offset.
					       payload_offset /* -displ */ ]);
			int rc = 0, payload_len =
				hdr->caplen -
				hdr->parsed_pkt.pkt_detail.offset.payload_offset -
				displ;

			if (payload_len > 0) {
				int i;
				struct ts_state state;

				if (debug) {
					printk
						("[PF_RING] Trying to match pattern [caplen=%d][len=%d][displ=%d][payload_offset=%d][",
						 hdr->caplen, payload_len, displ,
						 hdr->parsed_pkt.pkt_detail.offset.
						 payload_offset);

					for (i = 0; i < payload_len; i++)
						printk("[%d/%c]", i,
						       payload[i] & 0xFF);
					printk("]\n");
				}

				payload[payload_len] = '\0';

				if (debug)
					printk
						("[PF_RING] Attempt to match [%s]\n",
						 payload);

				for (i = 0; (i < MAX_NUM_PATTERN)
					     && (rule->pattern[i] != NULL); i++) {
					if (debug)
						printk
							("[PF_RING] Attempt to match pattern %d\n",
							 i);
					rc = (textsearch_find_continuous
					      (rule->pattern[i], &state,
					       payload,
					       payload_len) !=
					      UINT_MAX) ? 1 : 0;
					if (rc == 1)
						break;
				}

				if (debug)
					printk
						("[PF_RING] Match returned: %d [payload_len=%d][%s]\n",
						 rc, payload_len, payload);

				if (rc == 0)
					return (0);	/* No match */
			} else
				return (0);	/* No payload data */
		} else
			return (0);	/* No payload data */
	}

	if ((rule->rule.extended_fields.filter_plugin_id > 0)
	    && (rule->rule.extended_fields.filter_plugin_id < MAX_PLUGIN_ID)
	    && (plugin_registration[rule->rule.extended_fields.filter_plugin_id]
		!= NULL)
	    &&
	    (plugin_registration[rule->rule.extended_fields.filter_plugin_id]->
	     pfring_plugin_filter_skb != NULL)
		) {
		int rc;

		if (debug)
			printk("[PF_RING] rule->plugin_id [rule_id=%d]"
			       "[filter_plugin_id=%d][plugin_action=%d][ptr=%p]\n",
			       rule->rule.rule_id,
			       rule->rule.extended_fields.filter_plugin_id,
			       rule->rule.plugin_action.plugin_id,
			       plugin_registration[rule->rule.plugin_action.
						   plugin_id]);

		rc = plugin_registration[rule->rule.extended_fields.
					 filter_plugin_id]
			->pfring_plugin_filter_skb(the_ring, rule, hdr, skb,
						   &parse_memory_buffer[rule->rule.
									extended_fields.
									filter_plugin_id]);

		if (parse_memory_buffer
		    [rule->rule.extended_fields.filter_plugin_id])
			*free_parse_mem = 1;

		if (rc <= 0) {
			return (0);	/* No match */
		} else {
			*last_matched_plugin =
				rule->rule.extended_fields.filter_plugin_id;
			hdr->parsed_pkt.last_matched_plugin_id =
				rule->rule.extended_fields.filter_plugin_id;

			if (debug)
				printk
					("[PF_RING] [last_matched_plugin = %d][buffer=%p][len=%d]\n",
					 *last_matched_plugin,
					 parse_memory_buffer[rule->rule.
							     extended_fields.
							     filter_plugin_id],
					 parse_memory_buffer[rule->rule.
							     extended_fields.
							     filter_plugin_id] ?
					 parse_memory_buffer[rule->rule.
							     extended_fields.
							     filter_plugin_id]->
					 mem_len : 0);
		}
	}

	/* Action to be performed in case of match */
	if ((rule->rule.plugin_action.plugin_id != 0)
	    && (rule->rule.plugin_action.plugin_id < MAX_PLUGIN_ID)
	    && (plugin_registration[rule->rule.plugin_action.plugin_id] != NULL)
	    && (plugin_registration[rule->rule.plugin_action.plugin_id]->
		pfring_plugin_handle_skb != NULL)
		) {
		if (debug)
			printk
				("[PF_RING] Calling pfring_plugin_handle_skb()\n");

		plugin_registration[rule->rule.plugin_action.plugin_id]
			->pfring_plugin_handle_skb(the_ring, rule, NULL, hdr, skb,
						   rule->rule.extended_fields.
						   filter_plugin_id,
						   &parse_memory_buffer[rule->rule.
									extended_fields.
									filter_plugin_id],
						   behaviour);

		if (*last_matched_plugin == 0)
			*last_matched_plugin =
				rule->rule.plugin_action.plugin_id;

		if (parse_memory_buffer[rule->rule.plugin_action.plugin_id])
			*free_parse_mem = 1;
	} else {
		if (debug)
			printk
				("[PF_RING] Skipping pfring_plugin_handle_skb(plugin_action=%d)\n",
				 rule->rule.plugin_action.plugin_id);
		*behaviour = rule->rule.rule_action;
		if (debug)
			printk("[PF_RING] Rule %d behaviour: %d\n",
			       rule->rule.rule_id, rule->rule.rule_action);
	}

	if (debug) {
		printk
			("[PF_RING] MATCH: match_filtering_rule(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n",
			 hdr->parsed_pkt.vlan_id, hdr->parsed_pkt.l3_proto,
			 hdr->parsed_pkt.ipv4_src, hdr->parsed_pkt.l4_src_port,
			 hdr->parsed_pkt.ipv4_dst, hdr->parsed_pkt.l4_dst_port);
		printk
			("[PF_RING] [rule(vlan=%u, proto=%u, ip=%u-%u, port=%u-%u)(behaviour=%d)]\n",
			 rule->rule.core_fields.vlan_id,
			 rule->rule.core_fields.proto,
			 rule->rule.core_fields.host_low,
			 rule->rule.core_fields.host_high,
			 rule->rule.core_fields.port_low,
			 rule->rule.core_fields.port_high, *behaviour);
	}

	rule->rule.internals.jiffies_last_match = jiffies;
	return (1);		/* match */
}

/* ********************************** */

static void add_pkt_to_ring(struct sk_buff *skb,
			    struct ring_opt *pfr,
			    struct pfring_pkthdr *hdr,
			    int displ, short channel_id,
			    int offset, void *plugin_mem)
{
	char *ring_bucket;
	int idx;
	FlowSlot *theSlot;
	int32_t the_bit = 1 << channel_id;

#if defined(RING_DEBUG)
	printk
		("[PF_RING] --> add_pkt_to_ring(len=%d) [pfr->channel_id=%d][channel_id=%d]\n",
		 hdr->len, pfr->channel_id, channel_id);
#endif

	if (!pfr->ring_active)
		return;

	if ((pfr->channel_id != RING_ANY_CHANNEL)
	    && (channel_id != RING_ANY_CHANNEL)
	    && ((pfr->channel_id & the_bit) != the_bit))
		return;		/* Wrong channel */

	write_lock_bh(&pfr->ring_index_lock);
	idx = pfr->slots_info->insert_idx;
	idx++, theSlot = get_insert_slot(pfr);
	pfr->slots_info->tot_pkts++;

	if ((theSlot == NULL) || (theSlot->slot_state != 0)) {
		/* No room left */
		pfr->slots_info->tot_lost++;
		write_unlock_bh(&pfr->ring_index_lock);
		return;
	}

	ring_bucket = &theSlot->bucket;
	memcpy(ring_bucket, hdr, sizeof(struct pfring_pkthdr));	/* Copy extended packet header */

	if ((plugin_mem != NULL) && (offset > 0)) {
		memcpy(&ring_bucket[sizeof(struct pfring_pkthdr)], plugin_mem,
		       offset);
	}

	if (skb != NULL) {
		hdr->caplen = min(pfr->bucket_len - offset, hdr->caplen);

		if (hdr->caplen > 0) {
#if defined(RING_DEBUG)
			printk
				("[PF_RING] --> [caplen=%d][len=%d][displ=%d][parsed_header_len=%d][bucket_len=%d]\n",
				 hdr->caplen, hdr->len, displ,
				 hdr->parsed_header_len, pfr->bucket_len);
#endif
			skb_copy_bits(skb, -displ,
				      &ring_bucket[sizeof(struct pfring_pkthdr)
						   + offset], hdr->caplen);
		} else {
			if (hdr->parsed_header_len >= pfr->bucket_len) {
				static u_char print_once = 0;

				if (!print_once) {
					printk
						("[PF_RING] WARNING: the bucket len is [%d] shorter than the plugin parsed header [%d]\n",
						 pfr->bucket_len,
						 hdr->parsed_header_len);
					print_once = 1;
				}
			}
		}
	}

	if (idx == pfr->slots_info->tot_slots)
		pfr->slots_info->insert_idx = 0;
	else
		pfr->slots_info->insert_idx = idx;

#if defined(RING_DEBUG)
	printk("[PF_RING] ==> insert_idx=%d\n", pfr->slots_info->insert_idx);
#endif

	pfr->slots_info->tot_insert++;
	theSlot->slot_state = 1;
	write_unlock_bh(&pfr->ring_index_lock);

	/* wakeup in case of poll() */
	if (waitqueue_active(&pfr->ring_slots_waitqueue))
		wake_up_interruptible(&pfr->ring_slots_waitqueue);
}

/* ********************************** */

static int add_hdr_to_ring(struct ring_opt *pfr, struct pfring_pkthdr *hdr)
{
	read_lock_bh(&ring_mgmt_lock);
	add_pkt_to_ring(NULL, pfr, hdr, 0, 0, 0, NULL);
	read_unlock_bh(&ring_mgmt_lock);
	return (0);
}

/* ********************************** */

/* Free filtering placeholders */
static void free_parse_memory(struct parse_buffer *parse_memory_buffer[])
{
	int i;

	for (i = 1; i <= max_registered_plugin_id; i++)
		if (parse_memory_buffer[i]) {
			if (parse_memory_buffer[i]->mem != NULL) {
				kfree(parse_memory_buffer[i]->mem);
			}

			kfree(parse_memory_buffer[i]);
		}
}

/* ********************************** */

static int reflect_packet(struct sk_buff *skb,
			  struct ring_opt *pfr,
			  struct net_device *reflector_dev, int displ)
{
	int debug = 0;

	if (debug)
		printk("[PF_RING] reflect_packet called\n");

	if ((reflector_dev != NULL)
	    && (reflector_dev->flags & IFF_UP) /* Interface is up */ ) {
		int ret;

		skb->pkt_type = PACKET_OUTGOING, skb->dev = reflector_dev;
		/*
		  Avoid others to free the skb and crash
		  this because dev_queue_xmit (if successfull) is gonna
		  call kfree_skb that will free the skb if users (see below)
		  has not been incremented
		*/
		atomic_inc(&skb->users);
		skb->data -= displ, skb->len += displ;

		/*
		  NOTE
		  dev_queue_xmit() must be called with interrupts enabled
		  which means it can't be called with spinlocks held.
		*/
		ret = dev_queue_xmit(skb);
		skb->data += displ, skb->len -= displ;
		atomic_set(&pfr->num_ring_users, 0);	/* Done */
		/* printk("[PF_RING] --> ret=%d\n", ret); */
		if (ret == NETDEV_TX_OK)
			pfr->slots_info->tot_fwd_ok++;
		else {
			pfr->slots_info->tot_fwd_notok++;
			/*
			  Do not put the statement below in case of success
			  as dev_queue_xmit has already decremented users
			*/
			atomic_dec(&skb->users);
		}

		return (ret == NETDEV_TX_OK ? 0 : -ENETDOWN);
	} else
		pfr->slots_info->tot_fwd_notok++;

	return (-ENETDOWN);
}

/* ********************************** */

static int add_skb_to_ring(struct sk_buff *skb,
			   struct ring_opt *pfr,
			   struct pfring_pkthdr *hdr,
			   int is_ip_pkt, int displ, short channel_id)
{
	int fwd_pkt = 0;
	struct list_head *ptr, *tmp_ptr;
	u_int8_t free_parse_mem = 0;
	u_int last_matched_plugin = 0, debug = 0;
	u_char hash_found = 0;
	struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID] = { NULL };
	/* This is a memory holder
	   for storing parsed packet information
	   that will then be freed when the packet
	   has been handled
	*/

	if (!pfr->ring_active)
		return (-1);

	atomic_set(&pfr->num_ring_users, 1);

	/* [1] BPF Filtering (from af_packet.c) */
	if (pfr->bpfFilter != NULL) {
		unsigned res = 1, len;

		len = skb->len - skb->data_len;

		skb->data -= displ;
		res =
			sk_run_filter(skb, pfr->bpfFilter->insns,
				      pfr->bpfFilter->len);
		skb->data += displ;

		if (res == 0) {
			/* Filter failed */
#if defined(RING_DEBUG)
			printk
				("[PF_RING] add_skb_to_ring(skb): Filter failed [len=%d][tot=%llu]"
				 "[insertIdx=%d][pkt_type=%d][cloned=%d]\n",
				 (int)skb->len, pfr->slots_info->tot_pkts,
				 pfr->slots_info->insert_idx, skb->pkt_type,
				 skb->cloned);
#endif
			atomic_set(&pfr->num_ring_users, 0);
			return (-1);
		}
	}
#if defined(RING_DEBUG)
	printk("[PF_RING] add_skb_to_ring: [%s][displ=%d][len=%d][caplen=%d]"
	       "[is_ip_pkt=%d][%d -> %d][%p/%p]\n",
	       (skb->dev->name == NULL) ? skb->dev->name : "<NULL>",
	       displ, hdr->len, hdr->caplen,
	       is_ip_pkt, hdr->parsed_pkt.l4_src_port,
	       hdr->parsed_pkt.l4_dst_port, skb->dev, pfr->ring_netdev);
#endif

	/* ************************************* */

#if defined(RING_DEBUG)
	printk("[PF_RING] add_skb_to_ring(skb) [len=%d][tot=%llu][insertIdx=%d]"
	       "[pkt_type=%d][cloned=%d]\n",
	       (int)skb->len, pfr->slots_info->tot_pkts,
	       pfr->slots_info->insert_idx, skb->pkt_type, skb->cloned);
#endif

	/* Extensions */
	fwd_pkt = pfr->rules_default_accept_policy;
	/* printk("[PF_RING] rules_default_accept_policy: [fwd_pkt=%d]\n", fwd_pkt); */

	/* ************************** */

	/* [2] Filter packet according to rules */

	if (0)
		printk
			("[PF_RING] About to evaluate packet [len=%d][tot=%llu][insertIdx=%d]"
			 "[pkt_type=%d][cloned=%d]\n", (int)skb->len,
			 pfr->slots_info->tot_pkts, pfr->slots_info->insert_idx,
			 skb->pkt_type, skb->cloned);

	/* [2.1] Search the hash */
	if (pfr->filtering_hash != NULL) {
		u_int hash_idx;
		filtering_hash_bucket *hash_bucket;

		hash_idx = hash_pkt_header(hdr, 0, 0) % DEFAULT_RING_HASH_SIZE;
		hash_bucket = pfr->filtering_hash[hash_idx];

		while (hash_bucket != NULL) {
			if (hash_bucket_match(hash_bucket, hdr, 0, 0)) {
				hash_found = 1;
				break;
			} else
				hash_bucket = hash_bucket->next;
		}		/* while */

		if (hash_found) {
			rule_action_behaviour behaviour =
				forward_packet_and_stop_rule_evaluation;

			if ((hash_bucket->rule.plugin_action.plugin_id != 0)
			    && (hash_bucket->rule.plugin_action.plugin_id <
				MAX_PLUGIN_ID)
			    &&
			    (plugin_registration
			     [hash_bucket->rule.plugin_action.plugin_id] !=
			     NULL)
			    &&
			    (plugin_registration
			     [hash_bucket->rule.plugin_action.plugin_id]->
			     pfring_plugin_handle_skb != NULL)
				) {
				plugin_registration[hash_bucket->rule.
						    plugin_action.plugin_id]
					->pfring_plugin_handle_skb(pfr, NULL, hash_bucket, hdr, skb, 0	/* no plugin */
								   ,
								   &parse_memory_buffer
								   [hash_bucket->
								    rule.
								    plugin_action.
								    plugin_id],
								   &behaviour);

				if (parse_memory_buffer
				    [hash_bucket->rule.plugin_action.plugin_id])
					free_parse_mem = 1;
				last_matched_plugin =
					hash_bucket->rule.plugin_action.plugin_id;
				hdr->parsed_pkt.last_matched_plugin_id =
					hash_bucket->rule.plugin_action.plugin_id;
			}

			switch (behaviour) {
			case forward_packet_and_stop_rule_evaluation:
				fwd_pkt = 1;
				break;
			case dont_forward_packet_and_stop_rule_evaluation:
				fwd_pkt = 0;
				break;
			case execute_action_and_continue_rule_evaluation:
				hash_found = 0;	/* This way we also evaluate the list of rules */
				break;
			case forward_packet_add_rule_and_stop_rule_evaluation:
				fwd_pkt = 1;
				break;
			case reflect_packet_and_stop_rule_evaluation:
				fwd_pkt = 0;
				reflect_packet(skb, pfr,
					       hash_bucket->rule.internals.
					       reflector_dev, displ);
				break;
			case reflect_packet_and_continue_rule_evaluation:
				fwd_pkt = 0;
				reflect_packet(skb, pfr,
					       hash_bucket->rule.internals.
					       reflector_dev, displ);
				hash_found = 0;	/* This way we also evaluate the list of rules */
				break;
			}
		} else {
			/* printk("[PF_RING] Packet not found\n"); */
		}
	}

	/* [2.2] Search rules list */
	if ((!hash_found) && (pfr->num_filtering_rules > 0)) {
		list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
			filtering_rule_element *entry;
			rule_action_behaviour behaviour =
				forward_packet_and_stop_rule_evaluation;

			entry = list_entry(ptr, filtering_rule_element, list);

			if (match_filtering_rule(pfr, entry, hdr, skb, displ,
						 parse_memory_buffer,
						 &free_parse_mem,
						 &last_matched_plugin,
						 &behaviour)) {
				if (debug)
					printk("[PF_RING] behaviour=%d\n",
					       behaviour);

				if (behaviour ==
				    forward_packet_and_stop_rule_evaluation) {
					fwd_pkt = 1;
					break;
				} else if (behaviour ==
					   forward_packet_add_rule_and_stop_rule_evaluation)
				{
					filtering_hash_bucket *hash_bucket;

					fwd_pkt = 1;

					hash_bucket =
						(filtering_hash_bucket *) kcalloc(1,
										  sizeof
										  (filtering_hash_bucket),
										  GFP_ATOMIC);

					if (hash_bucket) {
						int rc = 0;

						hash_bucket->rule.vlan_id =
							hdr->parsed_pkt.vlan_id;
						hash_bucket->rule.proto =
							hdr->parsed_pkt.l3_proto;
						hash_bucket->rule.host_peer_a =
							hdr->parsed_pkt.ipv4_src;
						hash_bucket->rule.host_peer_b =
							hdr->parsed_pkt.ipv4_dst;
						hash_bucket->rule.port_peer_a =
							hdr->parsed_pkt.l4_src_port;
						hash_bucket->rule.port_peer_b =
							hdr->parsed_pkt.l4_dst_port;
						hash_bucket->rule.rule_action =
							forward_packet_and_stop_rule_evaluation;
						hash_bucket->rule.
							reflector_device_name[0] =
							'\0';
						hash_bucket->rule.internals.jiffies_last_match = jiffies;	/* Avoid immediate rule purging */
						hash_bucket->rule.internals.
							reflector_dev = NULL;

						rc = pfr->handle_hash_rule(pfr,
									   hash_bucket,
									   1
									   /* add_rule_from_plugin */
							);
						pfr->num_filtering_rules++;

						if (rc != 0) {
							kfree(hash_bucket);
							return (-1);
						} else {
							if (debug)
								printk
									("[PF_RING] Added rule: [%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][tot_rules=%d]\n",
									 ((hash_bucket->rule.host_peer_a >> 24) & 0xff), ((hash_bucket->rule.host_peer_a >> 16) & 0xff), ((hash_bucket->rule.host_peer_a >> 8) & 0xff), ((hash_bucket->rule.host_peer_a >> 0) & 0xff), hash_bucket->rule.port_peer_a, ((hash_bucket->rule.host_peer_b >> 24) & 0xff), ((hash_bucket->rule.host_peer_b >> 16) & 0xff), ((hash_bucket->rule.host_peer_b >> 8) & 0xff), ((hash_bucket->rule.host_peer_b >> 0) & 0xff), hash_bucket->rule.port_peer_b, pfr->num_filtering_rules);
						}
					}
					break;
				} else if (behaviour ==
					   dont_forward_packet_and_stop_rule_evaluation)
				{
					fwd_pkt = 0;
					break;
				}

				if (entry->rule.rule_action ==
				    forward_packet_and_stop_rule_evaluation) {
					fwd_pkt = 1;
					break;
				} else if (entry->rule.rule_action ==
					   dont_forward_packet_and_stop_rule_evaluation)
				{
					fwd_pkt = 0;
					break;
				} else if (entry->rule.rule_action ==
					   execute_action_and_continue_rule_evaluation)
				{
					/* The action has already been performed inside match_filtering_rule()
					   hence instead of stopping rule evaluation, the next rule
					   will be evaluated */
				} else if (entry->rule.rule_action ==
					   reflect_packet_and_stop_rule_evaluation)
				{
					fwd_pkt = 0;
					reflect_packet(skb, pfr,
						       entry->rule.internals.
						       reflector_dev, displ);
				} else if (entry->rule.rule_action ==
					   reflect_packet_and_continue_rule_evaluation)
				{
					fwd_pkt = 0;
					reflect_packet(skb, pfr,
						       entry->rule.internals.
						       reflector_dev, displ);
					break;
				}
			}
		}		/* for */
	}

	if (fwd_pkt) {
		/* We accept the packet: it needs to be queued */
		if (debug)
			printk("[PF_RING] Forwarding packet to userland\n");

		/* [3] Packet sampling */
		if (pfr->sample_rate > 1) {
			write_lock_bh(&pfr->ring_index_lock);
			pfr->slots_info->tot_pkts++;

			if (pfr->pktToSample == 0) {
				pfr->pktToSample = pfr->sample_rate;
			} else {
				pfr->pktToSample--;

#if defined(RING_DEBUG)
				printk
					("[PF_RING] add_skb_to_ring(skb): sampled packet [len=%d]"
					 "[tot=%llu][insertIdx=%d][pkt_type=%d][cloned=%d]\n",
					 (int)skb->len, pfr->slots_info->tot_pkts,
					 pfr->slots_info->insert_idx, skb->pkt_type,
					 skb->cloned);
#endif

				write_unlock_bh(&pfr->ring_index_lock);
				if (free_parse_mem)
					free_parse_memory(parse_memory_buffer);
				atomic_set(&pfr->num_ring_users, 0);
				return (-1);
			}

			write_unlock_bh(&pfr->ring_index_lock);
		}

		if (hdr->caplen > 0) {
			/* Copy the packet into the bucket */
			int offset;
			void *mem;

			if ((last_matched_plugin > 0)
			    && (parse_memory_buffer[last_matched_plugin] !=
				NULL)) {
				offset = hdr->parsed_header_len =
					parse_memory_buffer[last_matched_plugin]->
					mem_len;

				hdr->parsed_pkt.last_matched_plugin_id =
					last_matched_plugin;

#if defined(RING_DEBUG)
				printk
					("[PF_RING] --> [last_matched_plugin = %d][parsed_header_len=%d]\n",
					 last_matched_plugin,
					 hdr->parsed_header_len);
#endif

				if (offset > pfr->bucket_len)
					offset = hdr->parsed_header_len =
						pfr->bucket_len;

				mem =
					parse_memory_buffer[last_matched_plugin]->
					mem;
			} else
				offset = 0, hdr->parsed_header_len = 0, mem =
					NULL;

			add_pkt_to_ring(skb, pfr, hdr, displ, channel_id,
					offset, mem);
		}
	}
#if defined(RING_DEBUG)
	printk("[PF_RING] [pfr->slots_info->insert_idx=%d]\n",
	       pfr->slots_info->insert_idx);
#endif

	if (free_parse_mem)
		free_parse_memory(parse_memory_buffer);
	atomic_set(&pfr->num_ring_users, 0);

	return (0);
}

/* ********************************** */

static u_int hash_skb(ring_cluster_element * cluster_ptr,
		      struct sk_buff *skb, int displ)
{
	u_int idx;
	struct iphdr *ip;

	if (cluster_ptr->cluster.hashing_mode == cluster_round_robin) {
		idx = cluster_ptr->cluster.hashing_id++;
	} else {
		/* Per-flow clustering */
		if (skb->len > sizeof(struct iphdr) + sizeof(struct tcphdr)) {
			/*
			  skb->data+displ

			  Always points to to the IP part of the packet
			*/
			ip = (struct iphdr *)(skb->data + displ);
			idx = ip->saddr + ip->daddr + ip->protocol;

			if (ip->protocol == IPPROTO_TCP) {
				struct tcphdr *tcp =
					(struct tcphdr *)(skb->data + displ +
							  sizeof(struct iphdr));
				idx += tcp->source + tcp->dest;
			} else if (ip->protocol == IPPROTO_UDP) {
				struct udphdr *udp =
					(struct udphdr *)(skb->data + displ +
							  sizeof(struct iphdr));
				idx += udp->source + udp->dest;
			}
		} else
			idx = skb->len;
	}

	return (idx % cluster_ptr->cluster.num_cluster_elements);
}

/* ********************************** */

static int register_plugin(struct pfring_plugin_registration *reg)
{
	if (reg == NULL)
		return (-1);

#ifdef RING_DEBUG
	printk("[PF_RING] --> register_plugin(%d)\n", reg->plugin_id);
#endif

	if ((reg->plugin_id >= MAX_PLUGIN_ID) || (reg->plugin_id == 0))
		return (-EINVAL);

	if (plugin_registration[reg->plugin_id] != NULL)
		return (-EINVAL);	/* plugin already registered */
	else {
		plugin_registration[reg->plugin_id] = reg;
		plugin_registration_size++;

		max_registered_plugin_id =
			max(max_registered_plugin_id, reg->plugin_id);

		printk("[PF_RING] registered plugin [id=%d][max=%d][%p]\n",
		       reg->plugin_id, max_registered_plugin_id,
		       plugin_registration[reg->plugin_id]);
		try_module_get(THIS_MODULE);	/* Increment usage count */
		return (0);
	}
}

/* ********************************** */

int unregister_plugin(u_int16_t pfring_plugin_id)
{
	int i;

	if (pfring_plugin_id >= MAX_PLUGIN_ID)
		return (-EINVAL);

	if (plugin_registration[pfring_plugin_id] == NULL)
		return (-EINVAL);	/* plugin not registered */
	else {
		struct list_head *ptr, *tmp_ptr, *ring_ptr, *ring_tmp_ptr;

		plugin_registration[pfring_plugin_id] = NULL;
		plugin_registration_size--;

		read_lock_bh(&ring_mgmt_lock);
		list_for_each_safe(ring_ptr, ring_tmp_ptr, &ring_table) {
			struct ring_element *entry =
				list_entry(ring_ptr, struct ring_element, list);
			struct ring_opt *pfr = ring_sk(entry->sk);

			list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
				filtering_rule_element *rule;

				rule =
					list_entry(ptr, filtering_rule_element,
						   list);

				if (rule->rule.plugin_action.plugin_id ==
				    pfring_plugin_id) {
					if (plugin_registration
					    [pfring_plugin_id]
					    &&
					    plugin_registration
					    [pfring_plugin_id]->
					    pfring_plugin_free_ring_mem) {
						/* Custom free function */
						plugin_registration
							[pfring_plugin_id]->
							pfring_plugin_free_ring_mem
							(rule);
					} else {
						if (rule->plugin_data_ptr !=
						    NULL) {
							kfree(rule->
							      plugin_data_ptr);
							rule->plugin_data_ptr =
								NULL;
						}
					}

					rule->rule.plugin_action.plugin_id = 0;
				}
			}
		}
		read_unlock_bh(&ring_mgmt_lock);

		for (i = MAX_PLUGIN_ID - 1; i > 0; i--) {
			if (plugin_registration[i] != NULL) {
				max_registered_plugin_id = i;
				break;
			}
		}

		printk("[PF_RING] unregistered plugin [id=%d][max=%d]\n",
		       pfring_plugin_id, max_registered_plugin_id);
		module_put(THIS_MODULE);	/* Decrement usage count */
		return (0);
	}
}

/* ********************************** */

static int skb_ring_handler(struct sk_buff *skb,
			    u_char recv_packet,
			    u_char real_skb /* 1=real skb, 0=faked skb */ ,
			    short channel_id)
{
	struct sock *skElement;
	int rc = 0, is_ip_pkt;
	struct list_head *ptr;
	struct pfring_pkthdr hdr;
	int displ;
	struct sk_buff *skk = NULL;
	struct sk_buff *orig_skb = skb;

#ifdef PROFILING
	uint64_t rdt = _rdtsc(), rdt1, rdt2;
#endif

	if ((!skb)		/* Invalid skb */
	    ||((!enable_tx_capture) && (!recv_packet))) {
		/*
		  An outgoing packet is about to be sent out
		  but we decided not to handle transmitted
		  packets.
		*/
		return (0);
	}
#if defined(RING_DEBUG)
	if (1) {
		struct timeval tv;

		skb_get_timestamp(skb, &tv);
		printk
			("[PF_RING] skb_ring_handler() [skb=%p][%u.%u][len=%d][dev=%s][csum=%u]\n",
			 skb, (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec,
			 skb->len,
			 skb->dev->name == NULL ? "<NULL>" : skb->dev->name,
			 skb->csum);
	}
#endif

	if (channel_id == RING_ANY_CHANNEL /* Unknown channel */ )
		channel_id = skb->iif;	/* Might have been set by the driver */

#if defined (RING_DEBUG)
	/* printk("[PF_RING] channel_id=%d\n", channel_id); */
#endif

#ifdef PROFILING
	rdt1 = _rdtsc();
#endif

	if (recv_packet) {
		/* Hack for identifying a packet received by the e1000 */
		if (real_skb)
			displ = SKB_DISPLACEMENT;
		else
			displ = 0;	/* Received by the e1000 wrapper */
	} else
		displ = 0;

	is_ip_pkt = parse_pkt(skb, displ, &hdr);

	/* (de)Fragmentation <fusco@ntop.org> */
	if (enable_ip_defrag
	    && real_skb && is_ip_pkt && recv_packet && (ring_table_size > 0)) {
		struct sk_buff *cloned = NULL;
		struct iphdr *iphdr = NULL;

		skb_reset_network_header(skb);
		skb_reset_transport_header(skb);
		skb_set_network_header(skb, ETH_HLEN - displ);

		iphdr = ip_hdr(skb);

		if (iphdr) {
#if defined (RING_DEBUG)
			printk("[PF_RING] [version=%d] %X -> %X\n",
			       iphdr->version, iphdr->saddr, iphdr->daddr);
#endif
			if (iphdr->frag_off & htons(IP_MF | IP_OFFSET)) {
				if ((cloned =
				     skb_clone(skb, GFP_ATOMIC)) != NULL) {
#if defined (RING_DEBUG)
					int offset = ntohs(iphdr->frag_off);
					offset &= IP_OFFSET;
					offset <<= 3;

					printk
						("[PF_RING] There is a fragment to handle [proto=%d][frag_off=%u]"
						 "[ip_id=%u][network_header=%d][displ=%d]\n",
						 iphdr->protocol, offset,
						 ntohs(iphdr->id),
						 hdr.parsed_pkt.pkt_detail.offset.
						 l3_offset - displ, displ);
#endif
					skk = ring_gather_frags(cloned);

					if (skk != NULL) {
#if defined (RING_DEBUG)
						printk
							("[PF_RING] IP reasm on new skb [skb_len=%d]"
							 "[head_len=%d][nr_frags=%d][frag_list=%p]\n",
							 (int)skk->len,
							 skb_headlen(skk),
							 skb_shinfo(skk)->nr_frags,
							 skb_shinfo(skk)->
							 frag_list);
#endif
						skb = skk;
						parse_pkt(skb, displ, &hdr);
						hdr.len = hdr.caplen =
							skb->len + displ;
					} else {
						//printk("[PF_RING] Fragment queued \n");
						return (0);	/* mask rcvd fragments */
					}
				}
			} else {
#if defined (RING_DEBUG)
				printk
					("[PF_RING] Do not seems to be a fragmented ip_pkt[iphdr=%p]\n",
					 iphdr);
#endif
			}
		}
	}

	/* BD - API changed for time keeping */
	if (skb->tstamp.tv64 == 0)
		__net_timestamp(skb);
	hdr.ts = ktime_to_timeval(skb->tstamp);

	hdr.len = hdr.caplen = skb->len + displ;

	/* Avoid the ring to be manipulated while playing with it */
	read_lock_bh(&ring_mgmt_lock);

	/* [1] Check unclustered sockets */
	list_for_each(ptr, &ring_table) {
		struct ring_opt *pfr;
		struct ring_element *entry;

		entry = list_entry(ptr, struct ring_element, list);

		skElement = entry->sk;
		pfr = ring_sk(skElement);

		if ((pfr != NULL)
		    && (pfr->cluster_id == 0 /* No cluster */ )
		    && (pfr->ring_slots != NULL)
		    && ((pfr->ring_netdev == skb->dev)
			|| ((skb->dev->flags & IFF_SLAVE)
			    && (pfr->ring_netdev == skb->dev->master)))) {
			/* We've found the ring where the packet can be stored */
			int old_caplen = hdr.caplen;	/* Keep old lenght */
			hdr.caplen = min(hdr.caplen, pfr->bucket_len);
			add_skb_to_ring(skb, pfr, &hdr, is_ip_pkt, displ, channel_id);
			hdr.caplen = old_caplen;
			rc = 1;	/* Ring found: we've done our job */
		}
	}

	/* [2] Check socket clusters */
	list_for_each(ptr, &ring_cluster_list) {
		ring_cluster_element *cluster_ptr;
		struct ring_opt *pfr;

		cluster_ptr = list_entry(ptr, ring_cluster_element, list);

		if (cluster_ptr->cluster.num_cluster_elements > 0) {
			u_int skb_hash = hash_skb(cluster_ptr, skb, displ);

			skElement = cluster_ptr->cluster.sk[skb_hash];

			if (skElement != NULL) {
				pfr = ring_sk(skElement);

				if ((pfr != NULL)
				    && (pfr->ring_slots != NULL)
				    && ((pfr->ring_netdev == skb->dev)
					|| ((skb->dev->flags & IFF_SLAVE)
					    && (pfr->ring_netdev ==
						skb->dev->master)))) {
					/* We've found the ring where the packet can be stored */
					add_skb_to_ring(skb, pfr, &hdr,
							is_ip_pkt, displ,
							channel_id);
					rc = 1;	/* Ring found: we've done our job */
				}
			}
		}
	}

	read_unlock_bh(&ring_mgmt_lock);

#ifdef PROFILING
	rdt1 = _rdtsc() - rdt1;
#endif

#ifdef PROFILING
	rdt2 = _rdtsc();
#endif

	/* Fragment handling */
	if (skk != NULL)
		kfree_skb(skk);

	if (rc == 1) {
		if (transparent_mode) {
			rc = 0;
		} else {
			if (recv_packet && real_skb) {
#if defined(RING_DEBUG)
				printk("[PF_RING] kfree_skb()\n");
#endif

				kfree_skb(orig_skb);
			}
		}
	}
#ifdef PROFILING
	rdt2 = _rdtsc() - rdt2;
	rdt = _rdtsc() - rdt;

#if defined(RING_DEBUG)
	printk
		("[PF_RING] # cycles: %d [lock costed %d %d%%][free costed %d %d%%]\n",
		 (int)rdt, rdt - rdt1,
		 (int)((float)((rdt - rdt1) * 100) / (float)rdt), rdt2,
		 (int)((float)(rdt2 * 100) / (float)rdt));
#endif
#endif

	//printk("[PF_RING] Returned %d\n", rc);
	return (rc);		/*  0 = packet not handled */
}

/* ********************************** */

struct sk_buff skb;

static int buffer_ring_handler(struct net_device *dev, char *data, int len)
{
#if defined(RING_DEBUG)
	printk("[PF_RING] buffer_ring_handler: [dev=%s][len=%d]\n",
	       dev->name == NULL ? "<NULL>" : dev->name, len);
#endif

	skb.dev = dev, skb.len = len, skb.data = data, skb.data_len = len;
	skb.tstamp.tv64 = 0;

	return (skb_ring_handler
		(&skb, 1, 0 /* fake skb */ , -1 /* Unknown channel */ ));
}

/* ************************************* */

static void free_filtering_rule(filtering_rule * rule)
{
	if (rule->internals.reflector_dev != NULL)
		dev_put(rule->internals.reflector_dev);	/* Release device */
}

/* ************************************* */

static void free_filtering_hash_bucket(filtering_hash_bucket * bucket)
{
	if (bucket->plugin_data_ptr)
		kfree(bucket->plugin_data_ptr);

	if (bucket->rule.internals.reflector_dev != NULL)
		dev_put(bucket->rule.internals.reflector_dev);	/* Release device */
}

/* ************************************* */

static int handle_filtering_hash_bucket(struct ring_opt *pfr,
					filtering_hash_bucket * rule,
					u_char add_rule)
{
	u_int32_t hash_value = hash_pkt(rule->rule.vlan_id, rule->rule.proto,
					rule->rule.host_peer_a,
					rule->rule.host_peer_b,
					rule->rule.port_peer_a,
					rule->rule.port_peer_b) %
		DEFAULT_RING_HASH_SIZE;
	int rc = -1, debug = 0;

	if (debug)
		printk
			("[PF_RING] handle_filtering_hash_bucket(vlan=%u, proto=%u, "
			 "sip=%d.%d.%d.%d, sport=%u, dip=%d.%d.%d.%d, dport=%u, "
			 "hash_value=%u, add_rule=%d) called\n", rule->rule.vlan_id,
			 rule->rule.proto, ((rule->rule.host_peer_a >> 24) & 0xff),
			 ((rule->rule.host_peer_a >> 16) & 0xff),
			 ((rule->rule.host_peer_a >> 8) & 0xff),
			 ((rule->rule.host_peer_a >> 0) & 0xff),
			 rule->rule.port_peer_a,
			 ((rule->rule.host_peer_b >> 24) & 0xff),
			 ((rule->rule.host_peer_b >> 16) & 0xff),
			 ((rule->rule.host_peer_b >> 8) & 0xff),
			 ((rule->rule.host_peer_b >> 0) & 0xff),
			 rule->rule.port_peer_b, hash_value, add_rule);

	if (add_rule) {
		if (pfr->filtering_hash == NULL)
			pfr->filtering_hash = (filtering_hash_bucket **)
				kcalloc(DEFAULT_RING_HASH_SIZE,
					sizeof(filtering_hash_bucket *),
					GFP_ATOMIC);
		if (pfr->filtering_hash == NULL) {
			/* kfree(rule); */
			if (debug)
				printk
					("[PF_RING] handle_filtering_hash_bucket() returned %d [0]\n",
					 -EFAULT);
			return (-EFAULT);
		}
	}

	if (debug)
		printk
			("[PF_RING] handle_filtering_hash_bucket() allocated memory\n");

	if (pfr->filtering_hash == NULL) {
		/* We're trying to delete a hash rule from an empty hash */
		return (-EFAULT);
	}

	if (pfr->filtering_hash[hash_value] == NULL) {
		if (add_rule)
			pfr->filtering_hash[hash_value] = rule, rule->next =
				NULL, rc = 0;
		else {
			if (debug)
				printk("[PF_RING] handle_filtering_hash_bucket() returned %d [1]\n",
					 -1);
			return (-1);	/* Unable to find the specified rule */
		}
	} else {
		filtering_hash_bucket *prev = NULL, *bucket =
			pfr->filtering_hash[hash_value];

		while (bucket != NULL) {
			if (hash_filtering_rule_match
			    (&bucket->rule, &rule->rule)) {
				if (add_rule) {
					if (debug)
						printk("[PF_RING] Duplicate found "
						       "while adding rule: discarded\n");
					/* kfree(rule); */
					return (-EFAULT);
				} else {
					/* We've found the bucket to delete */

					if (debug)
						printk("[PF_RING] handle_filtering_hash_bucket()"
						       " found a bucket to delete: removing it\n");
					if (prev == NULL)
						pfr->
							filtering_hash[hash_value] =
							bucket->next;
					else
						prev->next = bucket->next;

					free_filtering_hash_bucket(bucket);
					kfree(bucket);
					if (debug)
						printk("[PF_RING] handle_filtering_hash_bucket() returned %d [2]\n",
							 0);
					return (0);
				}
			} else {
				prev = bucket;
				bucket = bucket->next;
			}
		}

		if (add_rule) {
			/* If the flow arrived until here, then this rule is unique */

			if (debug)
				printk("[PF_RING] handle_filtering_hash_bucket() "
				       "no duplicate rule found: adding the rule\n");
			rule->next = pfr->filtering_hash[hash_value];
			pfr->filtering_hash[hash_value] = rule;
			rc = 0;
		} else {
			/* The rule we searched for has not been found */
			rc = -1;
		}
	}

	if (debug)
		printk("[PF_RING] handle_filtering_hash_bucket() returned %d [3]\n",
			 rc);

	return (rc);
}

/* ********************************** */

static int ring_create(struct net *net,
		       struct socket *sock, int protocol)
{
	struct sock *sk;
	struct ring_opt *pfr;
	int err;

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_create()\n");
#endif

	/* Are you root, superuser or so ? */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	if (protocol != htons(ETH_P_ALL))
		return -EPROTONOSUPPORT;

	err = -ENOMEM;
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ring_proto);

	if (sk == NULL)
		goto out;

	sock->ops = &ring_ops;
	sock_init_data(sock, sk);

	err = -ENOMEM;
	ring_sk(sk) = ring_sk_datatype(kmalloc(sizeof(*pfr), GFP_KERNEL));

	if (!(pfr = ring_sk(sk))) {
		sk_free(sk);
		goto out;
	}
	memset(pfr, 0, sizeof(*pfr));
	pfr->ring_active = 0;	/* We activate as soon as somebody waits for packets */
	pfr->channel_id = RING_ANY_CHANNEL;
	pfr->bucket_len = DEFAULT_BUCKET_LEN;
	pfr->handle_hash_rule = handle_filtering_hash_bucket;
	init_waitqueue_head(&pfr->ring_slots_waitqueue);
	rwlock_init(&pfr->ring_index_lock);
	rwlock_init(&pfr->ring_rules_lock);
	atomic_set(&pfr->num_ring_users, 0);
	INIT_LIST_HEAD(&pfr->rules);

	sk->sk_family = PF_RING;
	sk->sk_destruct = ring_sock_destruct;

	ring_insert(sk);

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_create() - created\n");
#endif

	return (0);
out:
	return err;
}

/* *********************************************** */

static int ring_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct ring_opt *pfr = ring_sk(sk);
	struct list_head *ptr, *tmp_ptr;
	void *ring_memory_ptr;

	if (!sk)
		return 0;
	else
		pfr->ring_active = 0;

	while (atomic_read(&pfr->num_ring_users) > 0) {
		schedule();
	}

#if defined(RING_DEBUG)
	printk("[PF_RING] called ring_release\n");
#endif

	/*
	  The calls below must be placed outside the
	  write_lock_bh...write_unlock_bh block.
	*/
	sock_orphan(sk);
	ring_proc_remove(ring_sk(sk));

	write_lock(&ring_list_lock);

	if (pfr->ring_netdev && (pfr->ring_netdev->ifindex < MAX_NUM_DEVICES)) {
		struct list_head *ptr, *tmp_ptr;
		device_ring_list_element *entry;

		list_for_each_safe(ptr, tmp_ptr,
				   &device_ring_list[pfr->ring_netdev->
						     ifindex]) {
			entry = list_entry(ptr, device_ring_list_element, list);

			if (entry->the_ring == pfr) {
				list_del(ptr);
				kfree(entry);
				break;
			}
		}
	}

	write_unlock(&ring_list_lock);

	write_lock_bh(&ring_mgmt_lock);

	if (pfr->cluster_id != 0)
		remove_from_cluster(sk, pfr);

	ring_remove(sk);
	sock->sk = NULL;

	/* Free rules */
	list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
		filtering_rule_element *rule;
		int i;

		rule = list_entry(ptr, filtering_rule_element, list);

		if (plugin_registration[rule->rule.plugin_action.plugin_id]
		    && plugin_registration[rule->rule.plugin_action.plugin_id]->
		    pfring_plugin_free_ring_mem) {
			/* Custom free function */
			plugin_registration[rule->rule.plugin_action.
					    plugin_id]->
				pfring_plugin_free_ring_mem(rule);
		} else {
#ifdef DEBUG
			printk("[PF_RING] --> default_free [rule->rule.plugin_action.plugin_id=%d]\n",
				 rule->rule.plugin_action.plugin_id);
#endif
			if (rule->plugin_data_ptr != NULL) {
				kfree(rule->plugin_data_ptr);
				rule->plugin_data_ptr = NULL;
			}
		}

		for (i = 0; (i < MAX_NUM_PATTERN) && (rule->pattern[i] != NULL);
		     i++)
			textsearch_destroy(rule->pattern[i]);

		list_del(ptr);
		free_filtering_rule(&rule->rule);
		kfree(rule);
	}

	/* Filtering hash rules */
	if (pfr->filtering_hash) {
		int i;

		for (i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
			if (pfr->filtering_hash[i] != NULL) {
				filtering_hash_bucket *scan =
					pfr->filtering_hash[i], *next;

				while (scan != NULL) {
					next = scan->next;

					free_filtering_hash_bucket(scan);
					kfree(scan);
					scan = next;
				}
			}
		}

		kfree(pfr->filtering_hash);
	}

	/* Free the ring buffer later, vfree needs interrupts enabled */
	ring_memory_ptr = pfr->ring_memory;
	ring_sk(sk) = NULL;

	skb_queue_purge(&sk->sk_write_queue);
	sock_put(sk);
	write_unlock_bh(&ring_mgmt_lock);
	if (pfr->appl_name != NULL)
		kfree(pfr->appl_name);

	if (ring_memory_ptr != NULL) {
#if defined(RING_DEBUG)
		printk("[PF_RING] ring_release: rvfree\n");
#endif
		rvfree(ring_memory_ptr, pfr->slots_info->tot_mem);
	}

	kfree(pfr);

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_release: rvfree done\n");
#endif

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_release: done\n");
#endif

	return 0;
}

/* ********************************** */

/*
 * We create a ring for this socket and bind it to the specified device
 */
static int packet_ring_bind(struct sock *sk, struct net_device *dev)
{
	u_int the_slot_len;
	u_int32_t tot_mem;
	struct ring_opt *pfr = ring_sk(sk);
	// struct page *page, *page_end;

	if (!dev)
		return (-1);

#if defined(RING_DEBUG)
	printk("[PF_RING] packet_ring_bind(%s) called\n", dev->name);
#endif

	/* **********************************************

	 * *************************************
	 * *                                   *
	 * *        FlowSlotInfo               *
	 * *                                   *
	 * ************************************* <-+
	 * *        FlowSlot                   *   |
	 * *************************************   |
	 * *        FlowSlot                   *   |
	 * *************************************   +- num_slots
	 * *        FlowSlot                   *   |
	 * *************************************   |
	 * *        FlowSlot                   *   |
	 * ************************************* <-+
	 *
	 * ********************************************** */

	the_slot_len = sizeof(u_char)	/* flowSlot.slot_state */
#ifdef RING_MAGIC
		+ sizeof(u_char)
#endif
		+ sizeof(struct pfring_pkthdr)
		+ pfr->bucket_len /* flowSlot.bucket */ ;

	tot_mem = sizeof(FlowSlotInfo) + num_slots * the_slot_len;
	if (tot_mem % PAGE_SIZE)
		tot_mem += PAGE_SIZE - (tot_mem % PAGE_SIZE);

	pfr->ring_memory = rvmalloc(tot_mem);

	if (pfr->ring_memory != NULL) {
		printk("[PF_RING] successfully allocated %lu bytes at 0x%08lx\n",
			 (unsigned long)tot_mem, (unsigned long)pfr->ring_memory);
	} else {
		printk("[PF_RING] ERROR: not enough memory for ring\n");
		return (-1);
	}

	// memset(pfr->ring_memory, 0, tot_mem); // rvmalloc does the memset already

	pfr->slots_info = (FlowSlotInfo *) pfr->ring_memory;
	pfr->ring_slots = (char *)(pfr->ring_memory + sizeof(FlowSlotInfo));

	pfr->slots_info->version = RING_FLOWSLOT_VERSION;
	pfr->slots_info->slot_len = the_slot_len;
	pfr->slots_info->data_len = pfr->bucket_len;
	pfr->slots_info->tot_slots =
		(tot_mem - sizeof(FlowSlotInfo)) / the_slot_len;
	pfr->slots_info->tot_mem = tot_mem;
	pfr->slots_info->sample_rate = 1;

	printk("[PF_RING] allocated %d slots [slot_len=%d][tot_mem=%u]\n",
	       pfr->slots_info->tot_slots, pfr->slots_info->slot_len,
	       pfr->slots_info->tot_mem);

#ifdef RING_MAGIC
	{
		int i;

		for (i = 0; i < pfr->slots_info->tot_slots; i++) {
			unsigned long idx = i * pfr->slots_info->slot_len;
			FlowSlot *slot = (FlowSlot *) & pfr->ring_slots[idx];
			slot->magic = RING_MAGIC_VALUE;
			slot->slot_state = 0;
		}
	}
#endif

	pfr->sample_rate = 1;	/* No sampling */
	pfr->insert_page_id = 1, pfr->insert_slot_id = 0;
	pfr->rules_default_accept_policy = 1, pfr->num_filtering_rules = 0;
	ring_proc_add(ring_sk(sk), dev);

	if (dev->ifindex < MAX_NUM_DEVICES) {
		device_ring_list_element *elem;

		/* printk("[PF_RING] Adding ring to device index %d\n", dev->ifindex); */

		elem = kmalloc(sizeof(device_ring_list_element), GFP_ATOMIC);
		if (elem != NULL) {
			elem->the_ring = pfr;
			INIT_LIST_HEAD(&elem->list);
			write_lock(&ring_list_lock);
			list_add(&elem->list, &device_ring_list[dev->ifindex]);
			write_unlock(&ring_list_lock);
			/* printk("[PF_RING] Added ring to device index %d\n", dev->ifindex); */
		}
	}

	/*
	  IMPORTANT
	  Leave this statement here as last one. In fact when
	  the ring_netdev != NULL the socket is ready to be used.
	*/
	pfr->ring_netdev = dev;

	return (0);
}

/* ************************************* */

/* Bind to a device */
static int ring_bind(struct socket *sock, struct sockaddr *sa, int addr_len)
{
	struct sock *sk = sock->sk;
	struct net_device *dev = NULL;

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_bind() called\n");
#endif

	/*
	 *      Check legality
	 */
	if (addr_len != sizeof(struct sockaddr))
		return -EINVAL;
	if (sa->sa_family != PF_RING)
		return -EINVAL;
	if (sa->sa_data == NULL)
		return -EINVAL;

	/* Safety check: add trailing zero if missing */
	sa->sa_data[sizeof(sa->sa_data) - 1] = '\0';

#if defined(RING_DEBUG)
	printk("[PF_RING] searching device %s\n", sa->sa_data);
#endif

	if ((dev = __dev_get_by_name(&init_net,
				     sa->sa_data)) == NULL) {
#if defined(RING_DEBUG)
		printk("[PF_RING] search failed\n");
#endif
		return (-EINVAL);
	} else
		return (packet_ring_bind(sk, dev));
}

/* ************************************* */

/*
 * rvmalloc / rvfree / kvirt_to_pa copied from usbvideo.c
 */
unsigned long kvirt_to_pa(unsigned long adr)
{
	unsigned long kva, ret;

	kva = (unsigned long)page_address(vmalloc_to_page((void *)adr));
	kva |= adr & (PAGE_SIZE - 1);	/* restore the offset */
	ret = __pa(kva);
	return ret;
}

/* ************************************* */

static int do_memory_mmap(struct vm_area_struct *vma,
			  unsigned long size, char *ptr, u_int flags, int mode)
{
	unsigned long start;
	unsigned long page;

	/* we do not want to have this area swapped out, lock it */
	vma->vm_flags |= flags;
	start = vma->vm_start;

	while (size > 0) {
		int rc;

		if (mode == 0) {
			page = vmalloc_to_pfn(ptr);
			rc = remap_pfn_range(vma, start, page, PAGE_SIZE,
					     PAGE_SHARED);
		} else if (mode == 1) {
			rc = remap_pfn_range(vma, start,
					     __pa(ptr) >> PAGE_SHIFT,
					     PAGE_SIZE, PAGE_SHARED);
		} else {
			rc = remap_pfn_range(vma, start,
					     ((unsigned long)ptr) >> PAGE_SHIFT,
					     PAGE_SIZE, PAGE_SHARED);
		}

		if (rc) {
#if defined(RING_DEBUG)
			printk("[PF_RING] remap_pfn_range() failed\n");
#endif
			return (-EAGAIN);
		}

		start += PAGE_SIZE;
		ptr += PAGE_SIZE;
		if (size > PAGE_SIZE) {
			size -= PAGE_SIZE;
		} else {
			size = 0;
		}
	}

	return (0);
}

/* ************************************* */

static int ring_mmap(struct file *file,
		     struct socket *sock, struct vm_area_struct *vma)
{
	struct sock *sk = sock->sk;
	struct ring_opt *pfr = ring_sk(sk);
	int rc;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

	if (size % PAGE_SIZE) {
#if defined(RING_DEBUG)
		printk("[PF_RING] ring_mmap() failed: "
		       "len is not multiple of PAGE_SIZE\n");
#endif
		return (-EINVAL);
	}
#if defined(RING_DEBUG)
	printk("[PF_RING] ring_mmap() called, size: %ld bytes\n", size);
#endif

	if ((pfr->dna_device == NULL) && (pfr->ring_memory == NULL)) {
#if defined(RING_DEBUG)
		printk("[PF_RING] ring_mmap() failed: "
		       "mapping area to an unbound socket\n");
#endif
		return -EINVAL;
	}

	if (pfr->dna_device == NULL) {
		/* if userspace tries to mmap beyond end of our buffer, fail */
		if (size > pfr->slots_info->tot_mem) {
#if defined(RING_DEBUG)
			printk("[PF_RING] ring_mmap() failed: "
			       "area too large [%ld > %d]\n",
			       size, pfr->slots_info->tot_mem);
#endif
			return (-EINVAL);
		}
#if defined(RING_DEBUG)
		printk("[PF_RING] mmap [slot_len=%d]"
		       "[tot_slots=%d] for ring on device %s\n",
		       pfr->slots_info->slot_len, pfr->slots_info->tot_slots,
		       pfr->ring_netdev->name);
#endif

		if ((rc =
		     do_memory_mmap(vma, size, pfr->ring_memory, VM_LOCKED,
				    0)) < 0)
			return (rc);
	} else {
		/* DNA Device */
		if (pfr->dna_device == NULL)
			return (-EAGAIN);

		switch (pfr->mmap_count) {
		case 0:
			if ((rc = do_memory_mmap(vma, size,
						 (void *)pfr->dna_device->
						 packet_memory, VM_LOCKED,
						 1)) < 0)
				return (rc);
			break;

		case 1:
			if ((rc = do_memory_mmap(vma, size,
						 (void *)pfr->dna_device->
						 descr_packet_memory, VM_LOCKED,
						 1)) < 0)
				return (rc);
			break;

		case 2:
			if ((rc = do_memory_mmap(vma, size,
						 (void *)pfr->dna_device->
						 phys_card_memory,
						 (VM_RESERVED | VM_IO), 2)) < 0)
				return (rc);
			break;

		default:
			return (-EAGAIN);
		}

		pfr->mmap_count++;
	}

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_mmap succeeded\n");
#endif

	return 0;
}

/* ************************************* */

static int ring_recvmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
{
	FlowSlot *slot;
	struct ring_opt *pfr = ring_sk(sock->sk);
	u_int32_t queued_pkts, num_loops = 0;

#if defined(RING_DEBUG)
	printk("[PF_RING] ring_recvmsg called\n");
#endif

	pfr->ring_active = 1;
	slot = get_remove_slot(pfr);

	while ((queued_pkts = num_queued_pkts(pfr)) < MIN_QUEUED_PKTS) {
		wait_event_interruptible(pfr->ring_slots_waitqueue, 1);

#if defined(RING_DEBUG)
		printk("[PF_RING] -> ring_recvmsg returning %d "
		       "[queued_pkts=%d][num_loops=%d]\n",
			 slot->slot_state, queued_pkts, num_loops);
#endif

		if (queued_pkts > 0) {
			if (num_loops++ > MAX_QUEUE_LOOPS)
				break;
		}
	}

#if defined(RING_DEBUG)
	if (slot != NULL)
		printk("[PF_RING] ring_recvmsg is returning "
		       "[queued_pkts=%d][num_loops=%d]\n",
		       queued_pkts, num_loops);
#endif

	return (queued_pkts);
}

/* ************************************* */

unsigned int ring_poll(struct file *file,
		       struct socket *sock, poll_table * wait)
{
	FlowSlot *slot;
	struct ring_opt *pfr = ring_sk(sock->sk);
	int rc;

	/* printk("[PF_RING] -- poll called\n");  */

	if (pfr->dna_device == NULL) {
		/* PF_RING mode */

#if defined(RING_DEBUG)
		printk("[PF_RING] poll called (non DNA device)\n");
#endif

		pfr->ring_active = 1;
		slot = get_remove_slot(pfr);

		if ((slot != NULL) && (slot->slot_state == 0))
			poll_wait(file, &pfr->ring_slots_waitqueue, wait);

#if defined(RING_DEBUG)
		printk("[PF_RING] poll returning %d\n", slot->slot_state);
#endif

		if ((slot != NULL) && (slot->slot_state == 1))
			return (POLLIN | POLLRDNORM);
		else
			return (0);
	} else {
		/* DNA mode */

#if defined(RING_DEBUG)
		printk("[PF_RING] poll called on DNA device [%d]\n",
		       *pfr->dna_device->interrupt_received);
#endif

		if (pfr->dna_device->wait_packet_function_ptr == NULL)
			return (0);

		rc = pfr->dna_device->wait_packet_function_ptr(pfr->dna_device->
							       adapter_ptr, 1);
		if (rc == 0) {	/* No packet arrived yet */
			/* poll_wait(file, pfr->dna_device->packet_waitqueue, wait); */
		} else
			rc = pfr->dna_device->wait_packet_function_ptr(pfr->
								       dna_device->
								       adapter_ptr,
								       0);

		//*pfr->dna_device->interrupt_received = rc;
		if (rc == 0)
			rc = *pfr->dna_device->interrupt_received;

#if defined(RING_DEBUG)
		printk("[PF_RING] poll %s return [%d]\n",
		       pfr->ring_netdev->name,
		       *pfr->dna_device->interrupt_received);
#endif

		if (rc) {
			return (POLLIN | POLLRDNORM);
		} else {
			return (0);
		}
	}
}

/* ************************************* */

int add_to_cluster_list(ring_cluster_element * el, struct sock *sock)
{
	if (el->cluster.num_cluster_elements == CLUSTER_LEN)
		return (-1);	/* Cluster full */

	ring_sk_datatype(ring_sk(sock))->cluster_id = el->cluster.cluster_id;
	el->cluster.sk[el->cluster.num_cluster_elements] = sock;
	el->cluster.num_cluster_elements++;
	return (0);
}

/* ************************************* */

int remove_from_cluster_list(struct ring_cluster *el, struct sock *sock)
{
	int i, j;

	for (i = 0; i < CLUSTER_LEN; i++)
		if (el->sk[i] == sock) {
			el->num_cluster_elements--;

			if (el->num_cluster_elements > 0) {
				/* The cluster contains other elements */
				for (j = i; j < CLUSTER_LEN - 1; j++)
					el->sk[j] = el->sk[j + 1];

				el->sk[CLUSTER_LEN - 1] = NULL;
			} else {
				/* Empty cluster */
				memset(el->sk, 0, sizeof(el->sk));
			}

			return (0);
		}

	return (-1);		/* Not found */
}

/* ************************************* */

static int remove_from_cluster(struct sock *sock, struct ring_opt *pfr)
{
	struct list_head *ptr, *tmp_ptr;

#if defined(RING_DEBUG)
	printk("[PF_RING] --> remove_from_cluster(%d)\n", pfr->cluster_id);
#endif

	if (pfr->cluster_id == 0 /* 0 = No Cluster */ )
		return (0);	/* Noting to do */

	list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
		ring_cluster_element *cluster_ptr;

		cluster_ptr = list_entry(ptr, ring_cluster_element, list);

		if (cluster_ptr->cluster.cluster_id == pfr->cluster_id) {
			return (remove_from_cluster_list
				(&cluster_ptr->cluster, sock));
		}
	}

	return (-EINVAL);	/* Not found */
}

/* ************************************* */

static int add_to_cluster(struct sock *sock,
			  struct ring_opt *pfr, u_short cluster_id)
{
	struct list_head *ptr, *tmp_ptr;
	ring_cluster_element *cluster_ptr;

#ifndef RING_DEBUG
	printk("[PF_RING] --> add_to_cluster(%d)\n", cluster_id);
#endif

	if (cluster_id == 0 /* 0 = No Cluster */ )
		return (-EINVAL);

	if (pfr->cluster_id != 0)
		remove_from_cluster(sock, pfr);

	list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
		cluster_ptr = list_entry(ptr, ring_cluster_element, list);

		if (cluster_ptr->cluster.cluster_id == cluster_id) {
			return (add_to_cluster_list(cluster_ptr, sock));
		}
	}

	/* There's no existing cluster. We need to create one */
	if ((cluster_ptr = kmalloc(sizeof(ring_cluster_element),
				   GFP_KERNEL)) == NULL)
		return (-ENOMEM);

	INIT_LIST_HEAD(&cluster_ptr->list);

	cluster_ptr->cluster.cluster_id = cluster_id;
	cluster_ptr->cluster.num_cluster_elements = 1;
	cluster_ptr->cluster.hashing_mode = cluster_per_flow;	/* Default */
	cluster_ptr->cluster.hashing_id = 0;

	memset(cluster_ptr->cluster.sk, 0, sizeof(cluster_ptr->cluster.sk));
	cluster_ptr->cluster.sk[0] = sock;
	pfr->cluster_id = cluster_id;

	list_add(&cluster_ptr->list, &ring_cluster_list);	/* Add as first entry */

	return (0);		/* 0 = OK */
}

/* ************************************* */

static int ring_map_dna_device(struct ring_opt *pfr,
			       dna_device_mapping * mapping)
{
	int debug = 0;

	if (mapping->operation == remove_device_mapping) {
		pfr->dna_device = NULL;
		if (debug)
			printk("[PF_RING] ring_map_dna_device(%s): removed mapping\n",
				 mapping->device_name);
		return (0);
	} else {
		struct list_head *ptr, *tmp_ptr;
		dna_device_list *entry;

		list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
			entry = list_entry(ptr, dna_device_list, list);

			if ((!strcmp
			     (entry->dev.netdev->name, mapping->device_name))
			    && (entry->dev.channel_id == mapping->channel_id)) {
				pfr->dna_device =
					&entry->dev, pfr->ring_netdev =
					entry->dev.netdev;

				if (debug)
					printk("[PF_RING] ring_map_dna_device(%s):"
					       " added mapping\n",
						 mapping->device_name);

				return (0);
			}
		}
	}

	printk("[PF_RING] ring_map_dna_device(%s): mapping failed\n",
	       mapping->device_name);

	return (-1);
}

/* ************************************* */

static void purge_idle_hash_rules(struct ring_opt *pfr,
				  uint16_t rule_inactivity)
{
	int i, num_purged_rules = 0, debug = 0;
	unsigned long expire_jiffies =
		jiffies - msecs_to_jiffies(1000 * rule_inactivity);

	if (debug)
		printk("[PF_RING] purge_idle_hash_rules(rule_inactivity=%d)\n",
		       rule_inactivity);

	/* Free filtering hash rules inactive for more than rule_inactivity seconds */
	if (pfr->filtering_hash != NULL) {
		for (i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
			if (pfr->filtering_hash[i] != NULL) {
				filtering_hash_bucket *scan =
					pfr->filtering_hash[i], *next, *prev = NULL;

				while (scan != NULL) {
					next = scan->next;

					if (scan->rule.internals.jiffies_last_match < expire_jiffies) {
						/* Expired rule: free it */

						if (debug)
							printk ("[PF_RING] Purging hash rule "
								 /* "[last_match=%u][expire_jiffies=%u]" */
								 "[%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
								 /*
								   (unsigned int)scan->rule.internals.jiffies_last_match,
								   (unsigned int)expire_jiffies,
								 */
								 ((scan->rule.host_peer_a >> 24) & 0xff),
								 ((scan->rule.host_peer_a >> 16) & 0xff),
								 ((scan->rule.host_peer_a >> 8)  & 0xff),
								 ((scan->rule.host_peer_a >> 0)  & 0xff),
								 scan->rule.port_peer_a,
								 ((scan->rule.host_peer_b >> 24) & 0xff),
								 ((scan->rule.host_peer_b >> 16) & 0xff),
								 ((scan->rule.host_peer_b >> 8)  & 0xff),
								 ((scan->rule.host_peer_b >> 0) & 0xff),
								 scan->rule.port_peer_b,
								 num_purged_rules,
								 pfr->num_filtering_rules);

						free_filtering_hash_bucket
							(scan);
						kfree(scan);

						if (prev == NULL)
							pfr->filtering_hash[i] = next;
						else
							prev->next = next;

						pfr->num_filtering_rules--,
							num_purged_rules++;
					} else
						prev = scan;

					scan = next;
				}
			}
		}
	}

	if (debug)
		printk("[PF_RING] Purged %d hash rules [tot_rules=%d]\n",
		       num_purged_rules, pfr->num_filtering_rules);
}

/* ************************************* */

/* Code taken/inspired from core/sock.c */
static int ring_setsockopt(struct socket *sock,
			   int level, int optname,
			   char __user * optval, int optlen)
{
	struct ring_opt *pfr = ring_sk(sock->sk);
	int val, found, ret = 0 /* OK */ ;
	u_int cluster_id, debug = 0;
	int32_t channel_id;
	char applName[32 + 1];
	struct list_head *prev = NULL;
	filtering_rule_element *entry, *rule;
	u_int16_t rule_id, rule_inactivity;

	if (pfr == NULL)
		return (-EINVAL);

	if (get_user(val, (int *)optval))
		return -EFAULT;

	found = 1;

	switch (optname) {
	case SO_ATTACH_FILTER:
		ret = -EINVAL;

		printk("[PF_RING] BPF filter (%d)\n", 0);

		if (optlen == sizeof(struct sock_fprog)) {
			unsigned int fsize;
			struct sock_fprog fprog;
			struct sk_filter *filter;

			ret = -EFAULT;

			printk("[PF_RING] BPF filter (%d)\n", 1);
			/*
			  NOTE

			  Do not call copy_from_user within a held
			  splinlock (e.g. ring_mgmt_lock) as this caused
			  problems when certain debugging was enabled under
			  2.6.5 -- including hard lockups of the machine.
			*/
			if (copy_from_user(&fprog, optval, sizeof(fprog)))
				break;

			/* Fix below courtesy of Noam Dev <noamdev@gmail.com> */
			fsize = sizeof(struct sock_filter) * fprog.len;
			filter =
				kmalloc(fsize + sizeof(struct sk_filter),
					GFP_KERNEL);

			if (filter == NULL) {
				ret = -ENOMEM;
				break;
			}

			if (copy_from_user(filter->insns, fprog.filter, fsize))
				break;

			filter->len = fprog.len;

			if (sk_chk_filter(filter->insns, filter->len) != 0) {
				/* Bad filter specified */
				kfree(filter);
				pfr->bpfFilter = NULL;
				break;
			}

			/* get the lock, set the filter, release the lock */
			write_lock(&pfr->ring_rules_lock);
			pfr->bpfFilter = filter;
			write_unlock(&pfr->ring_rules_lock);
			ret = 0;

			//#if !defined(RING_DEBUG)
			printk
				("[PF_RING] BPF filter attached succesfully [len=%d]\n",
				 filter->len);
			//#endif

		}
		break;

	case SO_DETACH_FILTER:
		write_lock(&pfr->ring_rules_lock);
		found = 1;
		if (pfr->bpfFilter != NULL) {
			kfree(pfr->bpfFilter);
			pfr->bpfFilter = NULL;
		} else
			ret = -ENONET;
		write_unlock(&pfr->ring_rules_lock);
		break;

	case SO_ADD_TO_CLUSTER:
		if (optlen != sizeof(val))
			return -EINVAL;

		if (copy_from_user(&cluster_id, optval, sizeof(cluster_id)))
			return -EFAULT;

		write_lock(&pfr->ring_rules_lock);
		ret = add_to_cluster(sock->sk, pfr, cluster_id);
		write_unlock(&pfr->ring_rules_lock);
		break;

	case SO_REMOVE_FROM_CLUSTER:
		write_lock(&pfr->ring_rules_lock);
		ret = remove_from_cluster(sock->sk, pfr);
		write_unlock(&pfr->ring_rules_lock);
		break;

	case SO_SET_CHANNEL_ID:
		if (optlen != sizeof(channel_id))
			return -EINVAL;

		if (copy_from_user(&channel_id, optval, sizeof(channel_id)))
			return -EFAULT;

		pfr->channel_id = channel_id;
#if defined(RING_DEBUG)
		printk("[PF_RING] [pfr->channel_id=%d][channel_id=%d]\n",
		       pfr->channel_id, channel_id);
#endif
		ret = 0;
		break;

	case SO_SET_APPL_NAME:
		if (optlen >
		    sizeof(applName) /* Names should not be too long */ )
			return -EINVAL;

		if (copy_from_user(&applName, optval, optlen))
			return -EFAULT;

		if (pfr->appl_name != NULL)
			kfree(pfr->appl_name);
		pfr->appl_name = (char *)kmalloc(optlen + 1, GFP_ATOMIC);
		if (pfr->appl_name != NULL) {
			memcpy(pfr->appl_name, applName, optlen);
			pfr->appl_name[optlen] = '\0';
		}

		ret = 0;
		break;

	case SO_PURGE_IDLE_HASH_RULES:
		if (optlen != sizeof(rule_inactivity))
			return -EINVAL;

		if (copy_from_user
		    (&rule_inactivity, optval, sizeof(rule_inactivity)))
			return -EFAULT;
		else {
			if (rule_inactivity > 0) {
				write_lock(&pfr->ring_rules_lock);
				purge_idle_hash_rules(pfr, rule_inactivity);
				write_unlock(&pfr->ring_rules_lock);
			}
			ret = 0;
		}
		break;

	case SO_TOGGLE_FILTER_POLICY:
		if (optlen != sizeof(u_int8_t))
			return -EINVAL;
		else {
			u_int8_t new_policy;

			if (copy_from_user(&new_policy, optval, optlen))
				return -EFAULT;

			write_lock(&pfr->ring_rules_lock);
			pfr->rules_default_accept_policy = new_policy;
			write_unlock(&pfr->ring_rules_lock);
			/*
			  if (debug) 
			  printk("[PF_RING] SO_TOGGLE_FILTER_POLICY: default policy is %s\n",
			  pfr->rules_default_accept_policy ? "accept" : "drop");
			*/
		}
		break;

	case SO_ADD_FILTERING_RULE:
		if (debug)
			printk("[PF_RING] +++ SO_ADD_FILTERING_RULE(len=%d)\n",
			       optlen);

		if (optlen == sizeof(filtering_rule)) {
			struct list_head *ptr, *tmp_ptr;
			int idx = 0;

			if (debug)
				printk("[PF_RING] Allocating memory [filtering_rule]\n");

			rule =(filtering_rule_element *)
				kcalloc(1, sizeof(filtering_rule_element), GFP_KERNEL);

			if (rule == NULL)
				return -EFAULT;

			if (copy_from_user(&rule->rule, optval, optlen))
				return -EFAULT;

			INIT_LIST_HEAD(&rule->list);

			/* Rule checks */
			if (rule->rule.extended_fields.filter_plugin_id > 0) {
				int ret = 0;

				if (rule->rule.extended_fields.
				    filter_plugin_id >= MAX_PLUGIN_ID)
					ret = -EFAULT;
				else if (plugin_registration
					 [rule->rule.extended_fields.
					  filter_plugin_id] == NULL)
					ret = -EFAULT;

				if (ret != 0) {
					if (debug)
						printk("[PF_RING] Invalid filtering plugin [id=%d]\n",
							 rule->rule.extended_fields.filter_plugin_id);
					kfree(rule);
					return (ret);
				}
			}

			if (rule->rule.plugin_action.plugin_id > 0) {
				int ret = 0;

				if (rule->rule.plugin_action.plugin_id >=
				    MAX_PLUGIN_ID)
					ret = -EFAULT;
				else if (plugin_registration
					 [rule->rule.plugin_action.plugin_id] ==
					 NULL)
					ret = -EFAULT;

				if (ret != 0) {
					if (debug)
						printk("[PF_RING] Invalid action plugin [id=%d]\n",
							 rule->rule.plugin_action.plugin_id);
					kfree(rule);
					return (ret);
				}
			}

			if (rule->rule.reflector_device_name[0] != '\0') {
				rule->rule.internals.reflector_dev =
					dev_get_by_name(
						&init_net,
						rule->rule.reflector_device_name);

				if (rule->rule.internals.reflector_dev == NULL) {
					printk("[PF_RING] Unable to find device %s\n",
						 rule->rule.reflector_device_name);
					kfree(rule);
					return (-EFAULT);
				}
			} else
				rule->rule.internals.reflector_dev = NULL;

			/* Compile pattern if present */
			if (strlen(rule->rule.extended_fields.payload_pattern) > 0) {
				char *pattern =
					rule->rule.extended_fields.payload_pattern;

				printk("[PF_RING] About to compile pattern '%s'\n",
					 pattern);

				while (pattern && (idx < MAX_NUM_PATTERN)) {
					char *pipe = strchr(pattern, '|');

					if (pipe)
						pipe[0] = '\0';

#ifdef CONFIG_TEXTSEARCH
					rule->pattern[idx] = textsearch_prepare("bm"	/* Boyer-Moore */
										/* "kmp" = Knuth-Morris-Pratt */
										,
										pattern,
										strlen
										(pattern),
										GFP_KERNEL,
										TS_AUTOLOAD
#ifdef TS_IGNORECASE
										| TS_IGNORECASE
#endif
						);
#else
					rule->pattern[idx] = NULL;
#endif

					if (rule->pattern[idx])
						printk("[PF_RING] Compiled pattern '%s' [idx=%d]\n",
							 pattern, idx);

					if (pipe)
						pattern = &pipe[1], idx++;
					else
						break;
				}

			} else {
				rule->pattern[0] = NULL;
			}

			write_lock(&pfr->ring_rules_lock);
			if (debug)
				printk("[PF_RING] SO_ADD_FILTERING_RULE: About to add rule %d\n",
					 rule->rule.rule_id);

			/* Implement an ordered add */
			list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
				entry =
					list_entry(ptr, filtering_rule_element,
						   list);

				if (debug)
					printk("[PF_RING] SO_ADD_FILTERING_RULE: [current rule %d][rule to add %d]\n",
						 entry->rule.rule_id,
						 rule->rule.rule_id);

				if (entry->rule.rule_id == rule->rule.rule_id) {
					int i;

					memcpy(&entry->rule, &rule->rule,
					       sizeof(filtering_rule));

					for (i = 0; (i < MAX_NUM_PATTERN)
						     && (entry->pattern[i] != NULL); i++)
						textsearch_destroy(entry->pattern[i]);
					memcpy(entry->pattern, rule->pattern,
					       sizeof(struct ts_config *) * MAX_NUM_PATTERN);

					kfree(rule);
					rule = NULL;
					if (debug)
						printk("[PF_RING] SO_ADD_FILTERING_RULE: overwritten rule_id %d\n",
							 entry->rule.rule_id);
					break;
				} else if (entry->rule.rule_id >rule->rule.rule_id) {
					if (prev == NULL) {
						list_add(&rule->list, &pfr->rules);	/* Add as first entry */
						pfr->num_filtering_rules++;
						if (debug)
							printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as head rule\n",
								 rule->rule.
								 rule_id);
					} else {
						list_add(&rule->list, prev);
						pfr->num_filtering_rules++;
						if (debug)
							printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d\n",
								 rule->rule.
								 rule_id);
					}

					rule = NULL;
					break;
				} else
					prev = ptr;
			}	/* for */

			if (rule != NULL) {
				if (prev == NULL) {
					list_add(&rule->list, &pfr->rules);	/* Add as first entry */
					pfr->num_filtering_rules++;
					if (debug)
						printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as first rule\n",
							 rule->rule.rule_id);
				} else {
					list_add_tail(&rule->list, &pfr->rules);	/* Add as first entry */
					pfr->num_filtering_rules++;
					if (debug)
						printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as last rule\n",
							 rule->rule.rule_id);
				}
			}

			write_unlock(&pfr->ring_rules_lock);
		} else if (optlen == sizeof(hash_filtering_rule)) {
			/* This is a hash rule */
			filtering_hash_bucket *rule =
				(filtering_hash_bucket *) kcalloc(1,
								  sizeof(filtering_hash_bucket),
								  GFP_KERNEL);
			int rc;

			if (rule == NULL)
				return -EFAULT;

			if (copy_from_user(&rule->rule, optval, optlen))
				return -EFAULT;

			if (rule->rule.reflector_device_name[0] != '\0') {
				rule->rule.internals.reflector_dev =
					dev_get_by_name(
						&init_net,
						rule->rule.reflector_device_name);

				if (rule->rule.internals.reflector_dev == NULL) {
					printk("[PF_RING] Unable to find device %s\n",
					       rule->rule.reflector_device_name);
					kfree(rule);
					return (-EFAULT);
				}
			} else
				rule->rule.internals.reflector_dev = NULL;

			write_lock(&pfr->ring_rules_lock);
			rc = handle_filtering_hash_bucket(pfr, rule, 1 /* add */ );
			pfr->num_filtering_rules++;
			write_unlock(&pfr->ring_rules_lock);

			if (rc != 0) {
				kfree(rule);
				return (rc);
			}
		} else {
			printk("[PF_RING] Bad rule length (%d): discarded\n",
			       optlen);
			return -EFAULT;
		}
		break;

	case SO_REMOVE_FILTERING_RULE:
		if (optlen == sizeof(u_int16_t /* rule _id */ )) {
			/* This is a list rule */
			u_int8_t rule_found = 0;
			struct list_head *ptr, *tmp_ptr;

			if (copy_from_user(&rule_id, optval, optlen))
				return -EFAULT;

			write_lock(&pfr->ring_rules_lock);

			list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
				entry =	list_entry(ptr, filtering_rule_element, list);

				if (entry->rule.rule_id == rule_id) {
					int i;

					for (i = 0; (i < MAX_NUM_PATTERN)
						     && (entry->pattern[i] != NULL); i++)
						textsearch_destroy(entry->pattern[i]);
					list_del(ptr);
					pfr->num_filtering_rules--;

					if (entry->plugin_data_ptr)
						kfree(entry->plugin_data_ptr);
					free_filtering_rule(&entry->rule);
					kfree(entry);
					if (debug)
						printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d has been removed\n",
							 rule_id);
					rule_found = 1;
					break;
				}
			}	/* for */

			write_unlock(&pfr->ring_rules_lock);
			if (!rule_found) {
				if (debug)
					printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d does not exist\n",
						 rule_id);
				return -EFAULT;	/* Rule not found */
			}
		} else if (optlen == sizeof(hash_filtering_rule)) {
			/* This is a hash rule */
			filtering_hash_bucket rule;
			int rc;

			if (copy_from_user(&rule.rule, optval, optlen))
				return -EFAULT;

			write_lock(&pfr->ring_rules_lock);
			rc = handle_filtering_hash_bucket(pfr, &rule,
							  0 /* delete */ );
			pfr->num_filtering_rules--;
			write_unlock(&pfr->ring_rules_lock);
			if (rc != 0)
				return (rc);
		} else
			return -EFAULT;
		break;

	case SO_SET_SAMPLING_RATE:
		if (optlen != sizeof(pfr->sample_rate))
			return -EINVAL;

		if (copy_from_user
		    (&pfr->sample_rate, optval, sizeof(pfr->sample_rate)))
			return -EFAULT;
		break;

	case SO_ACTIVATE_RING:
		if (debug)
			printk("[PF_RING] * SO_ACTIVATE_RING *\n");
		found = 1, pfr->ring_active = 1;
		break;

	case SO_RING_BUCKET_LEN:
		if (optlen != sizeof(u_int32_t))
			return -EINVAL;
		else {
			if (copy_from_user(&pfr->bucket_len, optval, optlen))
				return -EFAULT;
		}
		break;

	case SO_MAP_DNA_DEVICE:
		if (optlen != sizeof(dna_device_mapping))
			return -EINVAL;
		else {
			dna_device_mapping mapping;

			if (copy_from_user(&mapping, optval, optlen))
				return -EFAULT;
			else
				ret = ring_map_dna_device(pfr, &mapping), found = 1;			
		}
		break;

	default:
		found = 0;
		break;
	}

	if (found)
		return (ret);
	else
		return (sock_setsockopt(sock, level, optname, optval, optlen));
}

/* ************************************* */

static int ring_getsockopt(struct socket *sock,
			   int level, int optname,
			   char __user * optval, int __user * optlen)
{
	int len, debug = 0;
	struct ring_opt *pfr = ring_sk(sock->sk);

	if (pfr == NULL)
		return (-EINVAL);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case SO_GET_RING_VERSION:
	{
		u_int32_t version = RING_VERSION_NUM;

		if (copy_to_user(optval, &version, sizeof(version)))
			return -EFAULT;
	}
	break;

	case PACKET_STATISTICS:
	{
		struct tpacket_stats st;

		if (len > sizeof(struct tpacket_stats))
			len = sizeof(struct tpacket_stats);

		st.tp_packets = pfr->slots_info->tot_insert;
		st.tp_drops = pfr->slots_info->tot_lost;

		if (copy_to_user(optval, &st, len))
			return -EFAULT;
		break;
	}

	case SO_GET_HASH_FILTERING_RULE_STATS:
	{
		int rc = -EFAULT;

		if (len >= sizeof(hash_filtering_rule)) {
			hash_filtering_rule rule;
			u_int hash_idx;

			if (pfr->filtering_hash == NULL) {
				printk("[PF_RING] so_get_hash_filtering_rule_stats(): no hash failure\n");
				return -EFAULT;
			}

			if (copy_from_user(&rule, optval, sizeof(rule))) {
				printk("[PF_RING] so_get_hash_filtering_rule_stats: copy_from_user() failure\n");
				return -EFAULT;
			}

			if (debug)
				printk("[PF_RING] so_get_hash_filtering_rule_stats"
					 "(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n",
					 rule.vlan_id, rule.proto,
					 rule.host_peer_a, rule.port_peer_a,
					 rule.host_peer_b,
					 rule.port_peer_b);

			hash_idx = hash_pkt(rule.vlan_id, rule.proto,
					    rule.host_peer_a,
					    rule.host_peer_b,
					    rule.port_peer_a,
					    rule.port_peer_b) %
				DEFAULT_RING_HASH_SIZE;

			if (pfr->filtering_hash[hash_idx] != NULL) {
				filtering_hash_bucket *bucket;

				read_lock(&pfr->ring_rules_lock);
				bucket = pfr->filtering_hash[hash_idx];

				if (debug)
					printk("[PF_RING] so_get_hash_filtering_rule_stats(): bucket=%p\n",
						 bucket);

				while (bucket != NULL) {
					if (hash_bucket_match_rule
					    (bucket, &rule)) {
						char *buffer =
							kmalloc(len,
								GFP_ATOMIC);

						if (buffer == NULL) {
							printk("[PF_RING] so_get_hash_filtering_rule_stats() no memory failure\n");
							rc = -EFAULT;
						} else {
							if ((plugin_registration[rule.plugin_action.plugin_id] == NULL)
							    ||
							    (plugin_registration
							     [rule.plugin_action.plugin_id]->pfring_plugin_get_stats
							     == NULL)) {
								printk
									("[PF_RING] Found rule but pluginId %d is not registered\n",
									 rule.plugin_action.plugin_id);
								rc = -EFAULT;
							} else
								rc = plugin_registration[rule.plugin_action.plugin_id]->
									pfring_plugin_get_stats(pfr, NULL, bucket, buffer, len);

							if (rc > 0) {
								if (copy_to_user(optval, buffer, rc)) {
									printk("[PF_RING] copy_to_user() failure\n");
									rc = -EFAULT;
								}
							}
						}
						break;
					} else
						bucket = bucket->next;
				}	/* while */

				read_unlock(&pfr->ring_rules_lock);
			} else {
				if (debug)
					printk("[PF_RING] so_get_hash_filtering_rule_stats(): entry not found [hash_idx=%d]\n",
						 hash_idx);
			}
		}

		return (rc);
		break;
	}

	case SO_GET_FILTERING_RULE_STATS:
	{
		char *buffer = NULL;
		int rc = -EFAULT;
		struct list_head *ptr, *tmp_ptr;
		u_int16_t rule_id;

		if (len < sizeof(rule_id))
			return -EINVAL;

		if (copy_from_user(&rule_id, optval, sizeof(rule_id)))
			return -EFAULT;

		if (debug)
			printk("[PF_RING] SO_GET_FILTERING_RULE_STATS: rule_id=%d\n",
				 rule_id);

		read_lock(&pfr->ring_rules_lock);
		list_for_each_safe(ptr, tmp_ptr, &pfr->rules) {
			filtering_rule_element *rule;

			rule =
				list_entry(ptr, filtering_rule_element,
					   list);
			if (rule->rule.rule_id == rule_id) {
				buffer = kmalloc(len, GFP_ATOMIC);

				if (buffer == NULL)
					rc = -EFAULT;
				else {
					if ((plugin_registration
					     [rule->rule.plugin_action.
					      plugin_id] == NULL)
					    ||
					    (plugin_registration
					     [rule->rule.plugin_action.
					      plugin_id]->
					     pfring_plugin_get_stats ==
					     NULL)) {
						printk("[PF_RING] Found rule %d but pluginId %d is not registered\n",
							 rule_id,
							 rule->rule.
							 plugin_action.
							 plugin_id);
						rc = -EFAULT;
					} else
						rc = plugin_registration
							[rule->rule.
							 plugin_action.
							 plugin_id]
							->
							pfring_plugin_get_stats
							(pfr, rule, NULL,
							 buffer, len);

					if (rc > 0) {
						if (copy_to_user
						    (optval, buffer,
						     rc)) {
							rc = -EFAULT;
						}
					}
				}
				break;
			}
		}

		read_unlock(&pfr->ring_rules_lock);
		if (buffer != NULL)
			kfree(buffer);

		/* printk("[PF_RING] SO_GET_FILTERING_RULE_STATS *END*\n"); */
		return (rc);
		break;
	}

	case SO_GET_MAPPED_DNA_DEVICE:
	{
		if (pfr->dna_device == NULL)
			return -EFAULT;

		if (len > sizeof(dna_device))
			len = sizeof(dna_device);

		if (copy_to_user(optval, pfr->dna_device, len))
			return -EFAULT;

		break;
	}

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	else
		return (0);
}

/* ************************************* */

u_int get_num_device_free_slots(int ifindex)
{
	int num = 0;

	if ((ifindex >= 0) && (ifindex < MAX_NUM_DEVICES)) {
		struct list_head *ptr, *tmp_ptr;
		device_ring_list_element *entry;

		list_for_each_safe(ptr, tmp_ptr, &device_ring_list[ifindex]) {
			int num_free_slots;

			entry = list_entry(ptr, device_ring_list_element, list);

			num_free_slots =
				get_num_ring_free_slots(entry->the_ring);

			if (num_free_slots == 0)
				return (0);
			else {
				if (num == 0)
					num = num_free_slots;
				else if (num > num_free_slots)
					num = num_free_slots;
			}
		}
	}

	return (num);
}

/* ************************************* */

void dna_device_handler(dna_device_operation operation,
			unsigned long packet_memory,
			u_int packet_memory_num_slots,
			u_int packet_memory_slot_len,
			u_int packet_memory_tot_len,
			void *descr_packet_memory,
			u_int descr_packet_memory_num_slots,
			u_int descr_packet_memory_slot_len,
			u_int descr_packet_memory_tot_len,
			u_int channel_id,
			void *phys_card_memory,
			u_int phys_card_memory_len,
			struct net_device *netdev,
			dna_device_model device_model,
			wait_queue_head_t * packet_waitqueue,
			u_int8_t * interrupt_received,
			void *adapter_ptr,
			dna_wait_packet wait_packet_function_ptr)
{
	int debug = 0;

	if (debug)
		printk("[PF_RING] dna_device_handler(%s)\n", netdev->name);

	if (operation == add_device_mapping) {
		dna_device_list *next;

		next = kmalloc(sizeof(dna_device_list), GFP_ATOMIC);
		if (next != NULL) {
			next->dev.packet_memory = packet_memory;
			next->dev.packet_memory_num_slots =
				packet_memory_num_slots;
			next->dev.packet_memory_slot_len =
				packet_memory_slot_len;
			next->dev.packet_memory_tot_len = packet_memory_tot_len;
			next->dev.descr_packet_memory = descr_packet_memory;
			next->dev.descr_packet_memory_num_slots =
				descr_packet_memory_num_slots;
			next->dev.descr_packet_memory_slot_len =
				descr_packet_memory_slot_len;
			next->dev.descr_packet_memory_tot_len =
				descr_packet_memory_tot_len;
			next->dev.phys_card_memory = phys_card_memory;
			next->dev.phys_card_memory_len = phys_card_memory_len;
			next->dev.channel_id = channel_id;
			next->dev.netdev = netdev;
			next->dev.device_model = device_model;
			next->dev.packet_waitqueue = packet_waitqueue;
			next->dev.interrupt_received = interrupt_received;
			next->dev.adapter_ptr = adapter_ptr;
			next->dev.wait_packet_function_ptr =
				wait_packet_function_ptr;
			list_add(&next->list, &ring_dna_devices_list);
			dna_devices_list_size++;
		} else {
			printk("[PF_RING] Could not kmalloc slot!!\n");
		}
	} else {
		struct list_head *ptr, *tmp_ptr;
		dna_device_list *entry;

		list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
			entry = list_entry(ptr, dna_device_list, list);

			if ((entry->dev.netdev == netdev)
			    && (entry->dev.channel_id == channel_id)) {
				list_del(ptr);
				kfree(entry);
				dna_devices_list_size--;
				break;
			}
		}
	}

	if (debug)
		printk("[PF_RING] dna_device_handler(%s): [dna_devices_list_size=%d]\n",
			 netdev->name, dna_devices_list_size);
}

/* ************************************* */

static int ring_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
#ifdef CONFIG_INET
	case SIOCGIFFLAGS:
	case SIOCSIFFLAGS:
	case SIOCGIFCONF:
	case SIOCGIFMETRIC:
	case SIOCSIFMETRIC:
	case SIOCGIFMEM:
	case SIOCSIFMEM:
	case SIOCGIFMTU:
	case SIOCSIFMTU:
	case SIOCSIFLINK:
	case SIOCGIFHWADDR:
	case SIOCSIFHWADDR:
	case SIOCSIFMAP:
	case SIOCGIFMAP:
	case SIOCSIFSLAVE:
	case SIOCGIFSLAVE:
	case SIOCGIFINDEX:
	case SIOCGIFNAME:
	case SIOCGIFCOUNT:
	case SIOCSIFHWBROADCAST:
		return (inet_dgram_ops.ioctl(sock, cmd, arg));
#endif

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

/* ************************************* */

static struct proto_ops ring_ops = {
	.family = PF_RING,
	.owner = THIS_MODULE,

	/* Operations that make no sense on ring sockets. */
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.sendpage = sock_no_sendpage,
	.sendmsg = sock_no_sendmsg,

	/* Now the operations that really occur. */
	.release = ring_release,
	.bind = ring_bind,
	.mmap = ring_mmap,
	.poll = ring_poll,
	.setsockopt = ring_setsockopt,
	.getsockopt = ring_getsockopt,
	.ioctl = ring_ioctl,
	.recvmsg = ring_recvmsg,
};

/* ************************************ */

static struct net_proto_family ring_family_ops = {
	.family = PF_RING,
	.create = ring_create,
	.owner = THIS_MODULE,
};

static struct proto ring_proto = {
	.name = "PF_RING",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct sock),
};

/* ************************************ */

static void __exit ring_exit(void)
{
	struct list_head *ptr, *tmp_ptr;
	struct ring_element *entry;

	list_for_each_safe(ptr, tmp_ptr, &ring_table) {
		entry = list_entry(ptr, struct ring_element, list);
		list_del(ptr);
		kfree(entry);
	}

	list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
		ring_cluster_element *cluster_ptr;

		cluster_ptr = list_entry(ptr, ring_cluster_element, list);

		list_del(ptr);
		kfree(cluster_ptr);
	}

	list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
		dna_device_list *elem;

		elem = list_entry(ptr, dna_device_list, list);

		list_del(ptr);
		kfree(elem);
	}

	set_register_pfring_plugin(NULL);
	set_unregister_pfring_plugin(NULL);
	set_skb_ring_handler(NULL);
	set_add_hdr_to_ring(NULL);
	set_buffer_ring_handler(NULL);
	set_read_device_pfring_free_slots(NULL);
	set_ring_dna_device_handler(NULL);
	sock_unregister(PF_RING);
	ring_proc_term();
	printk("[PF_RING] unloaded\n");
}

/* ************************************ */

static int __init ring_init(void)
{
	int i;

	printk("[PF_RING] Welcome to PF_RING %s\n"
	       "(C) 2004-09 L.Deri <deri@ntop.org>\n", RING_VERSION);

	INIT_LIST_HEAD(&ring_table);
	INIT_LIST_HEAD(&ring_cluster_list);
	INIT_LIST_HEAD(&ring_dna_devices_list);

	for (i = 0; i < MAX_NUM_DEVICES; i++)
		INIT_LIST_HEAD(&device_ring_list[i]);

	sock_register(&ring_family_ops);

	set_skb_ring_handler(skb_ring_handler);
	set_add_hdr_to_ring(add_hdr_to_ring);
	set_buffer_ring_handler(buffer_ring_handler);
	set_register_pfring_plugin(register_plugin);
	set_unregister_pfring_plugin(unregister_plugin);
	set_read_device_pfring_free_slots(get_num_device_free_slots);
	set_ring_dna_device_handler(dna_device_handler);

	if (get_buffer_ring_handler() != buffer_ring_handler) {
		printk("[PF_RING] set_buffer_ring_handler FAILED\n");

		set_skb_ring_handler(NULL);
		set_buffer_ring_handler(NULL);
		sock_unregister(PF_RING);
		return -1;
	} else {
		printk("[PF_RING] Ring slots       %d\n", num_slots);
		printk("[PF_RING] Slot version     %d\n",
		       RING_FLOWSLOT_VERSION);
		printk("[PF_RING] Capture TX       %s\n",
		       enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
		printk("[PF_RING] IP Defragment    %s\n",
		       enable_ip_defrag ? "Yes" : "No");
		printk("[PF_RING] Initialized correctly\n");

		ring_proc_init();
		return 0;
	}
}

module_init(ring_init);
module_exit(ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Deri <deri@ntop.org>");
MODULE_DESCRIPTION("Packet capture acceleration by means of a ring buffer");

MODULE_ALIAS_NETPROTO(PF_RING);
