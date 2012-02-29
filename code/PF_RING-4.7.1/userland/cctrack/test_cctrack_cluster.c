/*
 * test_cctrack_cluster.c
 *
 *  Created on: Sep 26, 2011
 *      Author: corny
 */


/* this is for testing purposes only, it leaks memory like hell!  */

#include <assert.h>
#include <signal.h>
#include "pfring.h"
#include "uthash.h"
#include "../../kernel/plugins/corny_conntrack_plugin.h"
#include "util.h"


typedef struct {
		uint32_t ip_src, ip_dst;
		uint16_t l4_src_port, l4_dst_port;
		uint8_t l4_proto;
	} record_key_t;

typedef struct {
	record_key_t key;
	long timestamp;
	uint32_t bytes_sampled;
	UT_hash_handle hh;
} record_t;


volatile int terminating = 0;


#define ERROR -1


void terminate(int signal);
int main(int argc, char *argv[]);

void printConnections(record_t **records){
	record_t *s;
	struct in_addr ip_src;
	struct in_addr ip_dst;
	char ipbuff1[sizeof("000.000.000.000")];
	char ipbuff2[sizeof("000.000.000.000")];

	printf("Entries of table %p\n", *records);
	for(s=*records; s != NULL; s=s->hh.next) {
		if(s->key.l4_proto == 6 /*TCP*/){
			ip_src.s_addr = endian_swap(s->key.ip_src);
			ip_dst.s_addr = endian_swap(s->key.ip_dst);

			strcpy(ipbuff1, inet_ntoa(ip_src));
			strcpy(ipbuff2, inet_ntoa(ip_dst));
			printf("%s:%d->%s:%d bytes_sampled: %d\n",
					ipbuff1, s->key.l4_src_port,
					ipbuff2, s->key.l4_dst_port,
					s->bytes_sampled);
		}
	}
}


/* get connection from the hashtable, insert this connection if it is
 * not in table
 */
record_t * getConnection(record_key_t *this_key, record_t **records){
	record_t l, *p = NULL;
	record_t *r = NULL;

	memset(&l, 0, sizeof(record_t)); /* zero fill! */
	l.key = *this_key;
	HASH_FIND(hh, *records, &l.key, sizeof(record_key_t), p);
	if(p==NULL){
		printf("new connection\n");
		r = (record_t*)malloc( sizeof(record_t) );
		if(!r) printf("Out of mem\n");
		memset(r, 0, sizeof(record_t)); /* zero fill! */
		r->key = *this_key;
		HASH_ADD(hh, *records, key, sizeof(record_key_t), r);
		HASH_FIND(hh, *records, &l.key, sizeof(record_key_t), p);
		if(r != p) printf("ERR hashing ptr\n");
	}
	if(!p) printf("ERR hashing\n");
	return p;
}

struct pthreadargs{
	pfring* ring_ptr;
	int flag;
};


void *pthread_cluster(void *ptr)
{
	record_t *records = NULL; /* hashtable */
	pfring* ring_ptr; 	/* Pointer to pfring struct */
	int ret;
	u_char *buffer; // pointer in the ring to a received packet
	struct pfring_pkthdr hdr;
	int flag = ((struct pthreadargs *)ptr)->flag;

	char ipbuff1[sizeof("000.000.000.000")];
	char ipbuff2[sizeof("000.000.000.000")];

	ring_ptr = ((struct pthreadargs *)ptr)->ring_ptr;

	if(flag){
		printf("%p is flagged thread\n", ring_ptr);
	}else{
		printf("%p is NOT flagged thread\n", ring_ptr);
	}


	while(!terminating) /* infinite loop */
	{
		ret = pfring_recv(ring_ptr,
				&buffer /* always supply valid pointer*/,
				0 /* buffer length*/,
				&hdr /* don't use packet header but NULL will seg fault here */,
				1 /* wait for incoming packet */);
		if(terminating) break;

		if(flag){
			puts("sleep");
			msleep(8000);
		}

		if(!ret){
			printf("pfring_recv returned with error %d\n", ret);
		}else{
			struct in_addr ip_src;
			struct in_addr ip_dst;

			buffer[hdr.extended_hdr.parsed_header_len+hdr.caplen] = '\0';
			if(hdr.extended_hdr.parsed_pkt.ip_version == 4){
				record_key_t con_key;
				record_t *con_ht;

				ip_src.s_addr = endian_swap(hdr.extended_hdr.parsed_pkt.ip_src.v4);
				ip_dst.s_addr = endian_swap(hdr.extended_hdr.parsed_pkt.ip_dst.v4);

				strcpy(ipbuff1, inet_ntoa(ip_src));
				strcpy(ipbuff2, inet_ntoa(ip_dst));

				printf("%p: packet %s -> %s: ", ring_ptr, ipbuff1, ipbuff2);

				//print_packet_ascii(&hdr, buffer);

				{
					uint32_t src_ip =  hdr.extended_hdr.parsed_pkt.ip_src.v4;
					uint16_t src_port = hdr.extended_hdr.parsed_pkt.l4_src_port;
					uint32_t dst_ip = hdr.extended_hdr.parsed_pkt.ip_dst.v4;
					uint16_t dst_port = hdr.extended_hdr.parsed_pkt.l4_dst_port;

					if(src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port)){
						con_key.ip_src = src_ip;
						con_key.ip_dst = dst_ip;
						con_key.l4_src_port = src_port;
						con_key.l4_dst_port = dst_port;
					}else{
						con_key.ip_src = dst_ip;
						con_key.ip_dst = src_ip;
						con_key.l4_src_port = dst_port;
						con_key.l4_dst_port = src_port;
					}

					con_key.l4_proto = hdr.extended_hdr.parsed_pkt.l3_proto;
				}

				con_ht = getConnection(&con_key, &records);

				/* l4 header + payload */
				con_ht->bytes_sampled +=
						hdr.caplen - hdr.extended_hdr.parsed_pkt.offset.l4_offset;
			}else{
				printf("packet ip version %d\n",
						hdr.extended_hdr.parsed_pkt.ip_version);
			}
		}
	}


	// Device Termination
	pfring_close(ring_ptr);
	printf("\nSuccessfully closed device.\n");

	printConnections(&records);

	return NULL;
}


int main(int argc, char *argv[])
{
	char *device;
	int add_cctrack_rule = 1; // set to 0 to disable cctrack kernel plugin

	int clusterID = 8;
	int clusters = 8;


	filtering_rule rule;

	pthread_t thread[clusters];

	pfring* ring_ptr;

	struct pthreadargs *parg;

	int i, rc;

	// Read command line parameters
	switch(argc) {

	case 1: device = "eth0"; // Default device value
		break;

	case 2: device = argv[1];
		break;

	default:
		printf("Usage: %s [device]\n", argv[0]);
		exit(1);
	}

	for(i=0; i < clusters; ++i){
		// Device Initialization

		//first add to cluster, then add rule!!


		ring_ptr = init_ring(device, 0);
		assert(ring_ptr != NULL);
		rc = pfring_set_cluster(ring_ptr, clusterID, cluster_per_flow);
		if(rc != 0){
			printf("ERROR: pfring_set_cluster returned %d\n", rc);
			exit(-1);
		}


		// Zeroing memory in order for it to work
		memset(&rule, 0, sizeof(filtering_rule));
		if(add_cctrack_rule){
			// Rule ID
			rule.rule_id = CCTRACK_RULE_ID;  /* Rules are processed in order from lowest to higest id */
			// Rule action
			rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
			// Extended fields
			rule.extended_fields.filter_plugin_id = CCTRACK_PLUGIN_ID;


			// Add rule to ring
			int errorcode = pfring_add_filtering_rule(ring_ptr, &rule);
			if (errorcode < 0)
			{
				printf("Error: Unable to add rule to pfring! Error code %d"
						"\tSocket %d. Error message: %s\n",
						errorcode, ring_ptr->fd, strerror(errno));
				pfring_close(ring_ptr);
				printf("Successfully closed device.\n");
				exit(-1);
			}
			else {
				printf("Successfully added rule to pfring.\n");
			}
		}

		parg = malloc(sizeof(struct pthreadargs));
		parg->flag = i%2;
		parg->ring_ptr = ring_ptr;

		printf("starting thread %d\n", i);
		if( (rc = pthread_create( &thread[i], NULL, &pthread_cluster, parg )) ){
			printf("Thread creation failed: %d\n", rc);
		}
	}


	// Set signal handlers
	signal(SIGINT, terminate);


	for(i=0; i < clusters; ++i){

		pthread_join( thread[i], NULL);
	}

	return 0;
}

void terminate(int signal)
{
	terminating = 1;
}
