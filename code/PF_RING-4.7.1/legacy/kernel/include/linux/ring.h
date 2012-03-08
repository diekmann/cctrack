/*
 * Definitions for packet ring
 *
 * 2004-09 Luca Deri <deri@ntop.org>
 */

#ifndef __RING_H
#define __RING_H

#define INCLUDE_MAC_INFO

#ifdef INCLUDE_MAC_INFO
#define SKB_DISPLACEMENT    14 /* Include MAC address information */
#else
#define SKB_DISPLACEMENT    0  /* Do NOT include MAC address information */
#endif

#define RING_MAGIC
#define RING_MAGIC_VALUE             0x88
#define RING_FLOWSLOT_VERSION          10

#define DEFAULT_BUCKET_LEN            128
#define MAX_NUM_DEVICES               256

/* Versioning */
#define RING_VERSION                "3.9.7"
#define RING_VERSION_NUM           0x030907

/* Set */
#define SO_ADD_TO_CLUSTER                99
#define SO_REMOVE_FROM_CLUSTER           100
#define SO_SET_STRING                    101
#define SO_ADD_FILTERING_RULE            102
#define SO_REMOVE_FILTERING_RULE         103
#define SO_TOGGLE_FILTER_POLICY          104
#define SO_SET_SAMPLING_RATE             105
#define SO_ACTIVATE_RING                 106
#define SO_RING_BUCKET_LEN               107
#define SO_SET_CHANNEL_ID                108
#define SO_PURGE_IDLE_HASH_RULES         109 /* inactivity (sec) */
#define SO_SET_APPL_NAME                 110

/* Get */
#define SO_GET_RING_VERSION              120
#define SO_GET_FILTERING_RULE_STATS      121
#define SO_GET_HASH_FILTERING_RULE_STATS 122
#define SO_GET_MAPPED_DNA_DEVICE         123

/* Map */
#define SO_MAP_DNA_DEVICE                130

#define REFLECTOR_NAME_LEN            8

/* *********************************** */

struct pkt_aggregation_info {
	u_int32_t num_pkts, num_bytes;
	struct timeval first_seen, last_seen;
};

/*
  Note that as offsets *can* be negative,
  please do not change them to unsigned
*/
struct pkt_offset {
	int16_t eth_offset; /* This offset *must* be added to all offsets below */
	int16_t vlan_offset;
	int16_t l3_offset;
	int16_t l4_offset;
	int16_t payload_offset;
};

struct pkt_parsing_info {
	/* Core fields (also used by NetFlow) */
	u_int16_t eth_type;   /* Ethernet type */
	u_int16_t vlan_id;    /* VLAN Id or NO_VLAN */
	u_int8_t  l3_proto, ipv4_tos;   /* Layer 3 protocol/TOS */
	u_int32_t ipv4_src, ipv4_dst;   /* IPv4 src/dst IP addresses */
	u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
	u_int8_t tcp_flags;   /* TCP flags (0 if not available) */

	u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
	union {
		struct pkt_offset offset; /* Offsets of L3/L4/payload elements */
		struct pkt_aggregation_info aggregation; /* Future or plugin use */
	} pkt_detail;
};

struct pfring_pkthdr {
	struct timeval ts;    /* time stamp */
	u_int32_t caplen;     /* length of portion present */
	u_int32_t len;        /* length this packet (off wire) */
	struct pkt_parsing_info parsed_pkt; /* packet parsing info */
	u_int16_t parsed_header_len; /* Extra parsing data before packet */
};

/* *********************************** */

#define MAX_PLUGIN_ID      64
#define MAX_PLUGIN_FIELDS  32

/* ************************************************* */

typedef struct {
	u_int8_t  proto;                   /* Use 0 for 'any' protocol */
	u_int16_t vlan_id;                 /* Use '0' for any vlan */
	u_int32_t host_low, host_high;     /* User '0' for any host. This is applied to both source
					      and destination. */
	u_int16_t port_low, port_high;     /* All ports between port_low...port_high
					      0 means 'any' port. This is applied to both source
					      and destination. This means that
					      (proto, sip, sport, dip, dport) matches the rule if
					      one in "sip & sport", "sip & dport" "dip & sport"
					      match. */
} filtering_rule_core_fields;

/* ************************************************* */

#define FILTER_PLUGIN_DATA_LEN   256

typedef struct {
	char payload_pattern[32];         /* If strlen(payload_pattern) > 0, the packet payload
					     must match the specified pattern */
	u_int16_t filter_plugin_id;       /* If > 0 identifies a plugin to which the datastructure
					     below will be passed for matching */
	char      filter_plugin_data[FILTER_PLUGIN_DATA_LEN];
	/* Opaque datastructure that is interpreted by the
	   specified plugin and that specifies a filtering
	   criteria to be checked for match. Usually this data
	   is re-casted to a more meaningful datastructure
	*/
} filtering_rule_extended_fields;

/* ************************************************* */

typedef struct {
	/* Plugin Action */
	u_int16_t plugin_id; /* ('0'=no plugin) id of the plugin associated with this rule */
} filtering_rule_plugin_action;

typedef enum {
	forward_packet_and_stop_rule_evaluation = 0,
	dont_forward_packet_and_stop_rule_evaluation,
	execute_action_and_continue_rule_evaluation,
	forward_packet_add_rule_and_stop_rule_evaluation,
	reflect_packet_and_stop_rule_evaluation,
	reflect_packet_and_continue_rule_evaluation
} rule_action_behaviour;

#if 0
typedef enum {
	forward_packet = 100,
	dont_forward_packet,
	use_rule_forward_policy
} packet_action_behaviour;
#endif

typedef struct {
	unsigned long jiffies_last_match;  /* Jiffies of the last rule match (updated by pf_ring) */
	void *reflector_dev; /* Reflector device (struct net_device*) */
} filtering_internals;

typedef struct {
	u_int16_t rule_id;                 /* Rules are processed in order from lowest to higest id */
	rule_action_behaviour rule_action; /* What to do in case of match */
	u_int8_t balance_id, balance_pool; /* If balance_pool > 0, then pass the packet above only if the
					      (hash(proto, sip, sport, dip, dport) % balance_pool)
					      = balance_id */
	filtering_rule_core_fields     core_fields;
	filtering_rule_extended_fields extended_fields;
	filtering_rule_plugin_action   plugin_action;
	char reflector_device_name[REFLECTOR_NAME_LEN];

	filtering_internals internals;   /* PF_RING internal fields */
} filtering_rule;

/* *********************************** */

/* Hash size used for precise packet matching */
#define DEFAULT_RING_HASH_SIZE     4096

/*
 * The hashtable contains only perfect matches: no
 * wildacards or so are accepted.
 */
typedef struct {
	u_int16_t vlan_id;
	u_int8_t  proto;
	u_int32_t host_peer_a, host_peer_b;
	u_int16_t port_peer_a, port_peer_b;

	rule_action_behaviour rule_action; /* What to do in case of match */
	filtering_rule_plugin_action plugin_action;
	char reflector_device_name[REFLECTOR_NAME_LEN];

	filtering_internals internals;   /* PF_RING internal fields */
} hash_filtering_rule;

/* ************************************************* */

typedef struct _filtering_hash_bucket {
	hash_filtering_rule           rule;
	void                          *plugin_data_ptr; /* ptr to a *continuous* memory area
							   allocated by the plugin */
	u_int16_t                     plugin_data_ptr_len;
	struct _filtering_hash_bucket *next;
} filtering_hash_bucket;

/* *********************************** */

#define RING_MIN_SLOT_SIZE    (60+sizeof(struct pfring_pkthdr))
#define RING_MAX_SLOT_SIZE    (1514+sizeof(struct pfring_pkthdr))

#ifndef min
#define min(a,b) ((a < b) ? a : b)
#endif

/* *********************************** */
/* False sharing reference: http://en.wikipedia.org/wiki/False_sharing */

typedef struct flowSlotInfo {
	u_int16_t version, sample_rate;
	u_int32_t tot_slots, slot_len, data_len, tot_mem;
	u_int64_t tot_pkts, tot_lost, tot_insert, tot_read;
	u_int64_t tot_fwd_ok, tot_fwd_notok;
	u_int32_t insert_idx;
	u_int8_t  padding[72]; /* Used to avoid false sharing */
	u_int32_t remove_idx;
	u_int32_t  padding2[31]; /* Used to avoid false sharing */
} FlowSlotInfo;

/* *********************************** */

typedef struct flowSlot {
#ifdef RING_MAGIC
	u_char     magic;      /* It must alwasy be zero */
#endif
	u_char     slot_state; /* 0=empty, 1=full   */
	u_char     bucket;     /* bucket[bucketLen] */
} FlowSlot;

/* *********************************** */

#ifdef __KERNEL__

FlowSlotInfo *getRingPtr(void);
int allocateRing(char *deviceName, u_int numSlots,
		 u_int bucketLen, u_int sampleRate);
unsigned int pollRing(struct file *fp, struct poll_table_struct * wait);
void deallocateRing(void);

/* ************************* */

#endif /* __KERNEL__ */

/* *********************************** */

#define PF_RING          27      /* Packet Ring */
#define SOCK_RING        PF_RING

/* ioctl() */
#define SIORINGPOLL      0x8888

/* ************************************************* */

typedef int (*dna_wait_packet)(void *adapter, int mode);

typedef enum {
	add_device_mapping = 0, remove_device_mapping
} dna_device_operation;

typedef enum {
	intel_e1000 = 0, intel_igb, intel_ixgbe
} dna_device_model;

typedef struct {
	unsigned long packet_memory;  /* Invalid in userland */
	u_int packet_memory_num_slots;
	u_int packet_memory_slot_len;
	u_int packet_memory_tot_len;
	void *descr_packet_memory;  /* Invalid in userland */
	u_int descr_packet_memory_num_slots;
	u_int descr_packet_memory_slot_len;
	u_int descr_packet_memory_tot_len;
	u_int channel_id;
	char *phys_card_memory; /* Invalid in userland */
	u_int phys_card_memory_len;
	struct net_device *netdev; /* Invalid in userland */
	dna_device_model device_model;
#ifdef __KERNEL__
	wait_queue_head_t *packet_waitqueue;
#else
	void *packet_waitqueue;
#endif
	u_int8_t *interrupt_received, in_use;
	void *adapter_ptr;
	dna_wait_packet wait_packet_function_ptr;
} dna_device;

typedef struct {
	dna_device_operation operation;
	char device_name[8];
	int32_t channel_id;
} dna_device_mapping;

/* ************************************************* */

#ifdef __KERNEL__

enum cluster_type {
	cluster_per_flow = 0,
	cluster_round_robin
};

#define CLUSTER_LEN       8

/*
 * A ring cluster is used group together rings used by various applications
 * so that they look, from the PF_RING point of view, as a single ring.
 * This means that developers can use clusters for sharing packets across
 * applications using various policies as specified in the hashing_mode
 * parameter.
 */
struct ring_cluster {
	u_short             cluster_id; /* 0 = no cluster */
	u_short             num_cluster_elements;
	enum cluster_type   hashing_mode;
	u_short             hashing_id;
	struct sock         *sk[CLUSTER_LEN];
};

/*
 * Linked-list of ring clusters.
 */
typedef struct {
	struct ring_cluster cluster;
	struct list_head list;
} ring_cluster_element;

typedef struct {
	dna_device dev;
	struct list_head list;
} dna_device_list;

/* ************************************************* */

/*
 * Linked-list of ring sockets.
 */
struct ring_element {
	struct list_head  list;
	struct sock      *sk;
};

/* ************************************************* */

struct ring_opt *pfr; /* Forward */

typedef int (*do_handle_filtering_hash_bucket)(struct ring_opt *pfr,
					       filtering_hash_bucket* rule,
					       u_char add_rule);

/* ************************************************* */

#define RING_ANY_CHANNEL  -1

/*
 * Ring options
 */
struct ring_opt {
	u_int8_t ring_active;
	struct net_device *ring_netdev;
	u_short ring_pid;
	u_int32_t ring_id;
	char *appl_name; /* String that identifies the application bound to the socket */

	/* Direct NIC Access */
	u_int8_t mmap_count;
	dna_device *dna_device;

	/* Cluster */
	u_short cluster_id; /* 0 = no cluster */

	/* Channel */
	int32_t channel_id;  /* -1 = any channel */

#if 0
	/* Reflector */
	struct net_device *reflector_dev; /* Reflector device */
#endif

	/* Packet buffers */
	unsigned long order;

	/* Ring Slots */
	void * ring_memory;
	u_int32_t bucket_len;
	FlowSlotInfo *slots_info; /* Points to ring_memory */
	char *ring_slots;         /* Points to ring_memory+sizeof(FlowSlotInfo) */

	/* Packet Sampling */
	u_int32_t pktToSample, sample_rate;

	/* BPF Filter */
	struct sk_filter *bpfFilter;

	/* Filtering Rules */
	filtering_hash_bucket **filtering_hash;
	u_int16_t num_filtering_rules;
	u_int8_t rules_default_accept_policy; /* 1=default policy is accept, drop otherwise */
	struct list_head rules;

	/* Locks */
	atomic_t num_ring_users;
	wait_queue_head_t ring_slots_waitqueue;
	rwlock_t ring_index_lock, ring_rules_lock;

	/* Indexes (Internal) */
	u_int insert_page_id, insert_slot_id;

	/* Function pointer */
	do_handle_filtering_hash_bucket handle_hash_rule;
};

/* **************************************** */

/*
 * Linked-list of device rings
 */
typedef struct {
	struct ring_opt *the_ring;
	struct list_head list;
} device_ring_list_element;

/* **************************************** */

#define MAX_NUM_PATTERN   32

typedef struct {
	filtering_rule rule;

#ifdef CONFIG_TEXTSEARCH
	struct ts_config *pattern[MAX_NUM_PATTERN];
#endif
	struct list_head list;

	/* Plugin action */
	void *plugin_data_ptr; /* ptr to a *continuous* memory area allocated by the plugin */
} filtering_rule_element;

struct parse_buffer {
	void      *mem;
	u_int16_t  mem_len;
};

/* **************************************** */

/* Plugins */
/* Execute an action (e.g. update rule stats) */
typedef int (*plugin_handle_skb)(struct ring_opt *the_ring,
				 filtering_rule_element *rule,       /* In case the match is on the list */
				 filtering_hash_bucket *hash_bucket, /* In case the match is on the hash */
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 u_int16_t filter_plugin_id,
				 struct parse_buffer **filter_rule_memory_storage,
				 rule_action_behaviour *behaviour);
/* Return 1/0 in case of match/no match for the given skb */
typedef int (*plugin_filter_skb)(struct ring_opt *the_ring,
				 filtering_rule_element *rule,
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 struct parse_buffer **filter_rule_memory_storage);
/* Get stats about the rule */
typedef int (*plugin_get_stats)(struct ring_opt *pfr,
				filtering_rule_element *rule,
				filtering_hash_bucket  *hash_bucket,
				u_char* stats_buffer, u_int stats_buffer_len);

/* Called when a ring is disposed */
typedef void (*plugin_free_ring_mem)(filtering_rule_element *rule);

struct pfring_plugin_registration {
	u_int16_t plugin_id;
	char name[16];          /* Unique plugin name (e.g. sip, udp) */
	char description[64];   /* Short plugin description */
	plugin_filter_skb    pfring_plugin_filter_skb; /* Filter skb: 1=match, 0=no match */
	plugin_handle_skb    pfring_plugin_handle_skb;
	plugin_get_stats     pfring_plugin_get_stats;
	plugin_free_ring_mem pfring_plugin_free_ring_mem;
};

typedef int   (*register_pfring_plugin)(struct pfring_plugin_registration
					*reg);
typedef int   (*unregister_pfring_plugin)(u_int16_t pfring_plugin_id);
typedef u_int (*read_device_pfring_free_slots)(int ifindex);
typedef void  (*handle_ring_dna_device)(dna_device_operation operation,
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
					wait_queue_head_t *packet_waitqueue,
					u_int8_t *interrupt_received,
					void *adapter_ptr,
					dna_wait_packet wait_packet_function_ptr);

extern register_pfring_plugin get_register_pfring_plugin(void);
extern unregister_pfring_plugin get_unregister_pfring_plugin(void);
extern read_device_pfring_free_slots get_read_device_pfring_free_slots(void);

extern void set_register_pfring_plugin(register_pfring_plugin the_handler);
extern void set_unregister_pfring_plugin(unregister_pfring_plugin the_handler);
extern void set_read_device_pfring_free_slots(read_device_pfring_free_slots the_handler);

extern int do_register_pfring_plugin(struct pfring_plugin_registration *reg);
extern int do_unregister_pfring_plugin(u_int16_t pfring_plugin_id);
extern int do_read_device_pfring_free_slots(int deviceidx);

extern handle_ring_dna_device get_ring_dna_device_handler(void);
extern void set_ring_dna_device_handler(handle_ring_dna_device
					the_dna_device_handler);
extern void do_ring_dna_device_handler(dna_device_operation operation,
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
				       wait_queue_head_t *packet_waitqueue,
				       u_int8_t *interrupt_received,
				       void *adapter_ptr,
				       dna_wait_packet wait_packet_function_ptr);

typedef int (*handle_ring_skb)(struct sk_buff *skb, u_char recv_packet,
			       u_char real_skb, short channel_id);
extern handle_ring_skb get_skb_ring_handler(void);
extern void set_skb_ring_handler(handle_ring_skb the_handler);
extern void do_skb_ring_handler(struct sk_buff *skb,
				u_char recv_packet, u_char real_skb);

typedef int (*handle_ring_buffer)(struct net_device *dev,
				  char *data, int len);
extern handle_ring_buffer get_buffer_ring_handler(void);
extern void set_buffer_ring_handler(handle_ring_buffer the_handler);
extern int do_buffer_ring_handler(struct net_device *dev,
				  char *data, int len);

typedef int (*handle_add_hdr_to_ring)(struct ring_opt *pfr,
				      struct pfring_pkthdr *hdr);
extern handle_add_hdr_to_ring get_add_hdr_to_ring(void);
extern void set_add_hdr_to_ring(handle_add_hdr_to_ring the_handler);
extern int do_add_hdr_to_ring(struct ring_opt *pfr, struct pfring_pkthdr *hdr);

#endif /* __KERNEL__  */


/* *********************************** */

#endif /* __RING_H */
