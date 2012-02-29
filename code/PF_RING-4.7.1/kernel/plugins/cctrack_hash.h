/*
 * cctrack_hash.h
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_HASH_H_
#define CCTRACK_HASH_H_


#include "cctrack.h"

// do not include "../linux/pf_ring.h", it causes strange errors!
#include <linux/in6.h> /* struct in6_addr */



typedef union {
	struct in6_addr v6;  /* IPv6 src/dst IP addresses (Network byte order) */
	u_int32_t v4;        /* IPv4 src/dst IP addresses */
} cc_ip_addr;



/* keep ip and port sorted to be bidirectional */
struct connection{
	/* the items the hash will be built upon */
	struct cctrack_key{
		/* IPv4 or IPv6. Valid values: 4,6 */
		uint8_t ip_type;

		/* src/dst IP addresses */
		cc_ip_addr   ip_src, ip_dst;

		/* Layer 4 src/dst ports */
		uint16_t l4_src_port, l4_dst_port;

		/* iso osi layer 4 protocol, like TCP,UDP,... */
		uint8_t l4_proto;
	} __attribute__((packed)) key;

	/* set to zero to indicate that this is an empty bucket
	 * set to 1 to indicate a deleted entry -- DOUBLE_HASHING only
	 * value not {0,1}:
	 * 		the time the last packed was received for this connection
	 * 		used for timeout
	 * */
	__kernel_time_t timestamp;

	/* number of bytes already sampled, set to 0xFFFFFFFF (-1)
	 * if enough bytes are sampled */
	uint32_t bytes_sampled;
};


/**
 * helper function
 */
int isIPv6(struct connection *con);


/* key contains the union field ip_addr,
 * the key can be compressed when an IPv4 key is hashed.
 * The hash functions expects the key the following way:
 * 		const void *key, u32 length
 * An array with all the key fields must be created and passed to the functions.
 * The array length can be calculated using the following two macros */
#define sizeof_cctrack_KeyV4 \
		(sizeof(u_int32_t) + sizeof(u_int32_t) + /*ip_src, ip_dst */ \
		sizeof(uint16_t) + sizeof(uint16_t) + /* l4_src_port, l4_dst_port */ \
		sizeof(uint8_t)) /* l4_proto */
#define sizeof_cctrack_KeyV6 \
		(sizeof(struct in6_addr) + sizeof(struct in6_addr) + /*ip_src, ip_dst */ \
		sizeof(uint16_t) + sizeof(uint16_t) + /* l4_src_port, l4_dst_port */ \
		sizeof(uint8_t)) /* l4_proto */


typedef struct connection bucket;

/*
 * Hash table:
 * General properties:
 * 		full connection structs are stored in the table
 * 		open addressing
 *
 * table properties:
 * 		a connections which excesses the timeout will be removed
 * 			-> if a packet for this connection arrives afterwards,
 * 			   a new connection will be created
 *		a connection with a bytes_sampled-field less than 0xFFFFFFFF
 *			still needs packets	sampled
 *		a connection with a bytes_sampled-field equal to 0xFFFFFFFF is
 *		completely sampled.
 *			this connection remains in the hash table until no new packets
 *			for this connection arrive and it timeouts
 *
 * Main operation: qiuConnection
 * query, insert update connection
 * returns:
 * 		pointer to new bucket if connection not in table
 * 			-> Set timestamp!
 * 		NULL if table is full or error occured
 * 		pointer to connection if connection is already in bucket.
 * 			-> Update timestamp!
 *
 * 	timeouted connections will be removed during this operation
 *
 *
 *
 */


/*
 * 0 LINEAR_PROBING
 * 1 QUADRATIC_PROBING
 * 2 DOUBLE_HASHING
 *
 *	LINEAR_PROBING: status working, entries can be deleted from hashtable
 *	QUADRATIC_PROBING: TODO
 *	DOUBLE_HASHING: status working, entries cannot be deleted in doubly hashing!
 *		do not use double hashing in production environments. Table fills up
 *		with deleted markers
 */
#define CCTRACK_COLLISION_RESOLUTION 0


/**
 * the hashtable
 */
struct cctrack_ht{
	bucket *ht;
	size_t size; /* number of buckets, power of two */

	u32 size_bitmask; /* size-1, all lower bits are set, can be used to speed
	up calculating mod as size is a power of two */


	/* initial values for hashing */
	u32 initval1;
	u32 initval2;

	/*
	 * locking of hashtable
	 * one simple spin lock for the whole table.
	 * locking hierarchy:
	 * 		ht_lock -> vars.lock
	 * 		vars.lock
	 * 	but never vars.lock -> ht_lock
	 */
	spinlock_t ht_lock;
};



/**
 * create a hashtable of given size in buckets
 * @param ht in
 * @param size the exact number of buckets the hashtable can store.
 * 	the size in memory will be sizeof(bucket)*size
 * 	must be a power of two
 * @return 0 on success, -1 else
 */
int cc_create_hashtable(struct cctrack_ht *ht, size_t size);

/**
 * returns the number of buckets that can be stored in a hashtable
 * of given size. Rounded to the next lower power of two
 */
size_t cctrack_get_number_of_buckets(size_t bytes);




/**
 * function properties explained above
 * @param ht hashtable
 * @param con connection to find the corresponding bucket for. Only con.key must
 * 		contain valid data
 * @param initval initial value for hashing function
 * @return a pointer to the bucket or NULL on error
 */
bucket * cctrack_qiuConnection(struct cctrack_ht *ht, struct connection *con);


/* DEBUG: print the hashtable via printk */
void dbg_printTable(struct cctrack_ht *ht);

#endif /* CCTRACK_HASH_H_ */
