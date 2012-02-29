/*
 * cctrack_hash.c
 *
 * Hash Table. Open addressing, linear probing, no dynamic memory allocation
 * during runtime.
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */



#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h> /* kmalloc */
#include <linux/jhash.h>
#include <linux/inet.h> /* inet_ntoa */
#include <linux/time.h> /*  getnstimeofday */

#include "cctrack_hash.h"
#include "cctrack_util.h"


/* ****************  local defines  ******************** */
#ifdef DEBUG
//#define DEBUG_VERBOSE
//#define DEBUG_HASHING
//#define DEBUG_HASHTABLE
//#define DEBUG_REMOVE
//#define DEBUG_COLLISION
#endif /* DEBUG */


#ifndef CCTRACK_COLLISION_RESOLUTION
#error "CCTRACK_COLLISION_RESOLUTION not defined"
#endif
#if CCTRACK_COLLISION_RESOLUTION > 2
#error "CCTRACK_COLLISION_RESOLUTION > 2"
#endif
#if CCTRACK_COLLISION_RESOLUTION < 0
#error "CCTRACK_COLLISION_RESOLUTION < 0"
#endif



/* ****************  function signatures ******************** */
/**
 * wrapper functions to be able to exchange the used hashing function
 */
static u32 inline do_cctrack_hash(const void *key, u32 length,
		u32 initval, u32 tablesize_mask);

/* second hashing function for collision */
static u32 inline do_cctrack_hash_2(const void *key, u32 length,
		u32 initval, u32 tablesize_mask);

/* double hashing */
static u32 inline do_cctrack_hash_collision(u32 hash1, u32 hash2, u32 j,
		u32 tablesize_mask);



/* ****************  hashtable creation ******************** */
size_t cctrack_get_number_of_buckets(size_t bytes)
{

	size_t buckets;
	size_t i;
	int msb;

	buckets = (bytes/sizeof(bucket));
	if(buckets == 0){
		printk("error: creating hashtable of size zero\n");
		return 0;
	}

	//round buckets to next lower power of two
	i=1;
	msb = (sizeof(size_t)*8)-1;
	for(i = i << ((sizeof(size_t)*8)-1); i>=0; i= i >> 1){
		if(i & buckets){
			break;
		}
		--msb;
	}
	buckets = 1;
	buckets = buckets << msb;

	return buckets;
}


int cc_create_hashtable(struct cctrack_ht *ht, size_t size){
	u8 *test = NULL;

	if(cctrack_get_number_of_buckets(size*sizeof(bucket)) != size){
		printk("Error: cc_create_hashtable size does not meet requirements\n");
		return -1;
	}

	if(size == 0){
		printk("Error: cc_create_hashtable size is zero\n");
		return -1;
	}

	ht->size_bitmask = (size-1);

	printk("allocating hashtable with %lu buckets (%lu KB)\n",
			size, size*sizeof(bucket)/1024);

	ht->ht = vmalloc(size*sizeof(bucket));
	ht->size = size;

	if(ht->ht==NULL){
		printk("Error: could not allocate memory for hashtable\n");
		return -1;
	}

	memset(ht->ht, 0, size*sizeof(bucket));

	for(test = (u8*)(ht->ht); test < (u8*)&ht->ht[ht->size -1]; ++test){
		if(*test != 0){
			printk("ERROR: hashtable not correclty initialized\n");
			printk("hashtable was at %p, error at %p\n", ht->ht, test);
			printk("hashtable end at %p\n",
					(void *)(((ulong)ht->ht)+size*sizeof(bucket)));
			return -1;
		}
	}

	return 0;
}



/* ***********  hashtable implementation helper functions ************* */
/* smaller version of connection.key to hash ipv4 */
struct cctrack_key_v4{
			uint8_t ip_type;
			u_int32_t  ip_src, ip_dst;
			uint16_t l4_src_port, l4_dst_port;
			uint8_t l4_proto;
		} __attribute__((packed));



/**
 * @param key_ptr out
 * @param key_len out
 * @param isIPv6 in
 * @param con in
 * @param key_v4 in
 */
static void inline generateKeyPtrForHash(void **key_ptr, u32 *key_len,
		int ipV6, struct connection *con, struct cctrack_key_v4 *key_v4)
{
	if(ipV6){
		*key_len = sizeof_cctrack_KeyV6;
		*key_ptr = &(con->key);
	}else{
		key_v4->ip_type = con->key.ip_type;
		key_v4->ip_src = con->key.ip_src.v4;
		key_v4->ip_dst = con->key.ip_dst.v4;
		key_v4->l4_src_port = con->key.l4_src_port;
		key_v4->l4_dst_port = con->key.l4_dst_port;
		key_v4->l4_proto = con->key.l4_proto;

		*key_len = sizeof_cctrack_KeyV4;
		*key_ptr = key_v4;
	}
}

int inline isIPv6(struct connection *con)
{
	if(con->key.ip_type == 4){
		return 0;
	}
	if(con->key.ip_type == 6){
		return 1;
	}

	printk("error: undefined ip_type. error in %s:%d\n",
			__FILE__, __LINE__);
	printk("ip_type was %d\n", con->key.ip_type);
	return 0;
}

static int inline IPv6equals(struct in6_addr *a, struct in6_addr *b)
{
	return a->s6_addr32[0] == b->s6_addr32[0] &&
			a->s6_addr32[1] == b->s6_addr32[1] &&
			a->s6_addr32[2] == b->s6_addr32[2] &&
			a->s6_addr32[3] == b->s6_addr32[3];
}

static int inline connectionEquals(struct connection *a, struct connection *b,
		int ipV6)
{
	return (a->key.ip_type == b->key.ip_type &&
				((ipV6 && IPv6equals(&a->key.ip_src.v6, &b->key.ip_src.v6)) ||
				a->key.ip_src.v4 == b->key.ip_src.v4) &&
				((ipV6 && IPv6equals(&a->key.ip_dst.v6, &b->key.ip_dst.v6)) ||
				a->key.ip_dst.v4 == b->key.ip_dst.v4) &&
			a->key.l4_src_port == b->key.l4_src_port &&
			a->key.l4_dst_port == b->key.l4_dst_port &&
			a->key.l4_proto == b->key.l4_proto);
}

static int inline isEmptyBucket(struct connection *con)
{
	return con->timestamp == 0;
}

static int inline isTimeoutedConnection(struct connection *con,
		__kernel_time_t __timeout, __kernel_time_t now)
{
	if(con->timestamp == 0 || con->timestamp == 1) return 0;

	return (now - con->timestamp) > __timeout;
}


static int inline isRemovedBucket(struct connection *con)
{
	/* LINEAR_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 0
	return 0;
#endif

	/* QUADRATIC_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 1
#error "not implemented"
#endif

		/* DOUBLE_HASHING */
#if CCTRACK_COLLISION_RESOLUTION == 2
	return con->timestamp == 1;
#endif
}



/**
 * @param con bucket to be removed
 * @param index index of con in hashtable
 * @param ht hashtable
 * @param key_v4 pointer to cctrack_key_v4 struct which can be reused
 * to calculate hashes
 */
static void removeConnection(struct connection *con,
	u32 index, struct cctrack_ht *ht,  struct cctrack_key_v4 *key_v4){

	/* LINEAR_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 0
	u32 err_index = index; //only used when table is full
	//int err_cnt = 0; //only used when table is full
	bucket *next;
	u32 next_hash;
	u32 next_index;
	void *next_key;
	u32 next_key_len;
	int next_isIPv6;
	int i=0;

	//variables in the loop
	//con = &ht->ht[index]
	//next = &ht->ht[next_bucket or next_hash]



#ifdef DEBUG
	if(!connectionEquals(con, &ht->ht[index], 1)){
		printk("ERR error in %s:%d\n",
			__FILE__, __LINE__);
	}
#endif

	next_index = index;
	/* free this bucket */
	memset(con, 0, sizeof(bucket));

	do{
#ifdef DEBUG_REMOVE
		printk("step: %d\n", i);
		dbg_printTable(ht);
#endif

		if(i++ > ht->size){
			//chances for table corruption are low
			cctrack_printk_once(KERN_ALERT
					"[ERROR] removeConnection: hashtable full\n"
					"[ERROR] hashtable completely full!!\n"
					"[ERROR] maybe corrupted table to free an entry!!\n"
					"[ERROR] reload module with greater hashtable!!\n"
					"removing bucket %d\n", err_index);
			memset(&ht->ht[err_index], 0, sizeof(bucket));
#ifdef DEBUG_REMOVE
			dbg_printTable(ht);
#endif
			break;

		}



		next_index = do_cctrack_hash_collision(next_index,
				0, 1, ht->size_bitmask);

		next = &ht->ht[next_index];
		if(isEmptyBucket(next)){
			/* next bucket is free, this bucket can be safely removed */
#ifdef DEBUG_REMOVE
			printk("empty %d BREAK\n", next_index);
#endif
			break;
		}else{
#ifdef DEBUG_REMOVE
			printk("not empty %d\n", next_index);
#endif

			next_isIPv6 = isIPv6(next);
			generateKeyPtrForHash(&next_key, &next_key_len,
					next_isIPv6, next, key_v4);
			next_hash = do_cctrack_hash(next_key, next_key_len,
					ht->initval1, ht->size_bitmask);

			/* next_hash between index and next_index modulo tablesize */
			if ( (index<=next_index) ?
					((index<next_hash)&&(next_hash<=next_index)) :
					((index<next_hash)||(next_hash<=next_index)) ){
#ifdef DEBUG_REMOVE
				printk("cont\n");
#endif
			}else{
				/* index <= next_index:
				 * 	case next_hash < index
				 * 		move next_hash to index that it can still be found
				 * 	case next_hash > next_index
				 * 		next_hash can be securely moved to index as it is
				 * 		in the wrong place
				 * index > next_index:
				 * 	wrap around
				 * 	case next_hash < index && next_hash > next_index
				 *		move next_hash to index that it can still be found
				 * */
#ifdef DEBUG_REMOVE
				printk("moving %d to %d\n", next_index, index);
#endif
				memcpy(con, next, sizeof(bucket));
				index = next_index;
				con = next;

				memset(con, 0, sizeof(bucket));
			}
		}
	}while(true);

#ifdef DEBUG_REMOVE
	printk("after remove\n");
	dbg_printTable(ht);
#endif
#endif


	/* QUADRATIC_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 1
#error "not implemented"
#endif

		/* DOUBLE_HASHING */
#if CCTRACK_COLLISION_RESOLUTION == 2
#error "DOUBLE_HASHING does not allow removal!"
	memset(con, 0, sizeof(bucket));
	con->timestamp = 1;
#endif
}


static void initBucket(struct connection *con, bucket *b){
	//assert: connection is sorted
	b->key.ip_type = con->key.ip_type;
	if(isIPv6(con)){
		b->key.ip_src.v6 = con->key.ip_src.v6;
		b->key.ip_dst.v6 = con->key.ip_dst.v6;
	}else{
		b->key.ip_src.v4 = con->key.ip_src.v4;
		b->key.ip_dst.v4 = con->key.ip_dst.v4;
	}
	b->key.l4_src_port = con->key.l4_src_port;
	b->key.l4_dst_port = con->key.l4_dst_port;
	b->key.l4_proto = con->key.l4_proto;
	b->timestamp = 0;
	b->bytes_sampled = 0;
}

static void dbg_l4_proto_toString(char *buff, uint8_t l4_proto){
	switch(l4_proto){
	case 2:
		strcpy(buff, "IGMP");
		break;
	case 6:
		strcpy(buff, "TCP");
		break;
	case 17:
		strcpy(buff, "UDP");
		break;
	default:
		strcpy(buff, "???");
		break;
	}
}


static void dbg_printConnection(const char *prefix,struct connection *con){
	char proto[8];

	dbg_l4_proto_toString(proto, con->key.l4_proto);

	if(isIPv6(con)){
		printk("%s: %pI6.%d -> %pI6.%d %d %s\n", prefix,
				&con->key.ip_src.v6, con->key.l4_src_port,
				&con->key.ip_dst.v6, con->key.l4_dst_port,
				con->key.l4_proto, proto);
	}else{
		uint32_t ip_src, ip_dst;
		ip_src = endian_swap(con->key.ip_src.v4);
		ip_dst = endian_swap(con->key.ip_dst.v4);
		printk("%s: %pI4:%d -> %pI4:%d %d %s\n", prefix,
				&ip_src, con->key.l4_src_port,
				&ip_dst, con->key.l4_dst_port,
				con->key.l4_proto, proto);
	}
}

void dbg_printTable(struct cctrack_ht *ht){
	size_t i;
	struct timespec tv;
	__kernel_time_t __timeout;

	u32 hash;
	void *key;
	u32 key_len;
	int IPv6;
	struct cctrack_key_v4 key_v4;

	__timeout = timeout; //global param

	getnstimeofday(&tv);

	printk("dbg_printTable:\n");
	for(i=0; i < ht->size; ++i){

		if(isTimeoutedConnection(&ht->ht[i], __timeout, tv.tv_sec)){
			IPv6 = isIPv6(&ht->ht[i]);
			generateKeyPtrForHash(&key, &key_len, IPv6, &ht->ht[i], &key_v4);
			hash = do_cctrack_hash(key, key_len, ht->initval1, ht->size_bitmask);
			printk("[%lu] hash %u\n", i, hash);
			dbg_printConnection("  timeouted", &ht->ht[i]);
		}

		if(!isEmptyBucket(&ht->ht[i]) && ! isRemovedBucket(&ht->ht[i]) &&
				!isTimeoutedConnection(&ht->ht[i], __timeout, tv.tv_sec)){
			IPv6 = isIPv6(&ht->ht[i]);
			generateKeyPtrForHash(&key, &key_len, IPv6, &ht->ht[i], &key_v4);
			hash = do_cctrack_hash(key, key_len, ht->initval1, ht->size_bitmask);
			printk("[%lu] hash %u\n", i, hash);
			dbg_printConnection("  connection", &ht->ht[i]);
			printk("  bytes sampled: %x ts: %ld (%ld sec old)\n",
					ht->ht[i].bytes_sampled,
					ht->ht[i].timestamp,
					(tv.tv_sec - ht->ht[i].timestamp));
		}
	}
}




/* ****************  hashtable public interface ******************** */
bucket * cctrack_qiuConnection(struct cctrack_ht *ht, struct connection *con)
{
	/* the working bucket */
	bucket * entry = NULL;

	/* a bucket to remember a free slot in the hashtable.
	 * Used to remember the position of the first deleted entry to
	 * overwrite this entry if a connection is found to be new and must
	 * be inserted in the table */
	bucket * free_entry = NULL;


	int ipV6 = isIPv6(con);
	int i;

	/* only calculate second hash if we need to */
	int collision = 0;
	u32 hash1;
	u32 hash2=0;
	u32 collision_hash; /* the index of the bucket */

	__kernel_time_t my_timeout;
	u32 initval1;
	u32 initval2;

	/* a smaller version of cctrack_key for IPv4 to build the hash value */
	struct cctrack_key_v4 key_v4;
	u32 key_len = 0;
	void *key_ptr = NULL;

	struct timespec now;

#ifdef DEBUG_COLLISION
	int collision_cnt = 0;
#endif


	my_timeout = timeout; //global param

	initval1 = ht->initval1;
	initval2 = ht->initval2;

	getnstimeofday(&now);

#ifdef DEBUG_VERBOSE
	dbg_printConnection("cctrack_qiuConnection", con);
#endif

	generateKeyPtrForHash(&key_ptr, &key_len, ipV6, con, &key_v4);
	hash1 = do_cctrack_hash(key_ptr, key_len, initval1, ht->size_bitmask);

#ifdef DEBUG
	if(hash1 >= ht->size){
		printk("Index Out Of Bounds\n");
		return NULL;
	}
#endif


	entry = &(ht->ht[hash1]);

	collision_hash = hash1;
	i=1;
	do{
#ifdef DEBUG_HASHING
		printk("testing bucket %u\n", collision_hash);
#endif
		if(i > ht->size/2){
#ifdef DEBUG_VERBOSE
			printk("Hash table full!\n");
#endif
			entry = NULL;
			break;
		}

		//handle timeout before testing for entry
		/* remove timeouted connection to clean up table */
		if(isTimeoutedConnection(entry, my_timeout, now.tv_sec)){
			removeConnection(entry, collision_hash, ht, &key_v4);
		}


#if CCTRACK_COLLISION_RESOLUTION == 2
		/* remember position of free entry */
		if((free_entry == NULL) && isRemovedBucket(entry)){
			free_entry = entry;
		}
#endif

		/* new connection, not in table */
		if(isEmptyBucket(entry)){
#ifdef DEBUG_VERBOSE
			printk("new connection\n");
#endif
			if(free_entry != NULL){
				entry = free_entry;
			}
			initBucket(con, entry);
			break;
		}

		/* found entry */
		if(connectionEquals(entry, con, ipV6)){
#ifdef DEBUG_VERBOSE
			printk("existing connection\n");
#endif
			break;
		}

		/* collision: next bucket */
#ifdef DEBUG_VERBOSE
		printk("collision for bucket %u\n", collision_hash);
#endif
#ifdef DEBUG_COLLISION
		++collision_cnt;
#endif
		if(!collision){
			collision = 1;
			hash2 = do_cctrack_hash_2(key_ptr, key_len,
					initval2, ht->size_bitmask);
		}

		collision_hash = do_cctrack_hash_collision(hash1, hash2, i,
				ht->size_bitmask);
		entry = &ht->ht[collision_hash];

		++i;
	}while(true);

#ifdef DEBUG_HASHTABLE
	dbg_printTable(ht);
#endif
#ifdef DEBUG_COLLISION
	printk("cctrack: collisions %d \n", collision_cnt);
#endif
	return entry;

}


/* **************  hashtable hashing helper functions ****************** */
static u32 inline do_cctrack_hash(const void *key, u32 length,
		u32 initval, u32 tablesize_mask)
{

#ifdef DEBUG
	if(!is_power_of_two(tablesize_mask+1))
		printk("Error! tablesize_mask not a power of two\n");
#endif

	//return jhash(key, length, initval) % tablesize;
	// tablesize is a power of two
	return jhash(key, length, initval) & tablesize_mask;
}


static u32 inline do_cctrack_hash_2(const void *key, u32 length,
		u32 initval, u32 tablesize_mask)
{

	/* LINEAR_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 0
		return 0;
#endif


	/* QUADRATIC_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 1
#error "untested"
		return 1;
#endif

		/* DOUBLE_HASHING */
#if CCTRACK_COLLISION_RESOLUTION == 2
		u32 hash = jhash(key, length, initval) & tablesize_mask;
#ifdef DEBUG
	if(!is_power_of_two(tablesize_mask+1))
		printk("Error! tablesize_mask not a power of two\n");
#endif
		if(hash == 0){
			return 1;
		}else{
			return hash;
		}
#endif
}


static u32 inline do_cctrack_hash_collision(u32 hash1, u32 hash2, u32 j,
		u32 tablesize_mask)
{
#ifdef DEBUG
	if(!is_power_of_two(tablesize_mask+1))
		printk("Error! tablesize_mask not a power of two\n");
#endif

	/* LINEAR_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 0
#ifdef DEBUG
	if(hash2 != 0)
		printk("Error! hash2 should be zero when linear probing\n");
#endif
		return (hash1 +j)  & tablesize_mask;
#endif


	/* QUADRATIC_PROBING */
#if CCTRACK_COLLISION_RESOLUTION == 1
#error "untested"
#endif

		/* DOUBLE_HASHING */
#if CCTRACK_COLLISION_RESOLUTION == 2
#ifdef DEBUG
		if(hash2 == 0) printk("ERROR: hash2==0\n");
#ifdef DEBUG_HASHING
		printk("double hashing: (%x + %d*%x)  & (%x)\n",
				hash1, j, hash2, tablesize_mask);
#endif
#endif
		//http://citeseerx.ist.psu.edu/
		//	viewdoc/download?doi=10.1.1.119.628&rep=rep1&type=pdf
		//enhanced double hashing as if
		// hash2 is a power of 2, performance is bad
		// enahnced part is "+ j*(j*j-1)/6"
		return (hash1 + j*hash2)  & tablesize_mask;
#endif
}

