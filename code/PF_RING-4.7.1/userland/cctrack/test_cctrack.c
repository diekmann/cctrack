/*
 * test_cctrack.c
 *
 *  Created on: Jul 26, 2011
 *      Author: corny
 *
 *  thx to gasser for this template
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

record_t *records = NULL; /* hashtable */


#define ERROR -1

// Pointer to pfring struct
pfring* ring_ptr;

void terminate(int signal);
int main(int argc, char *argv[]);


/* get connection from the hashtable, insert this connection if it is
 * not in table
 */
record_t * getConnection(record_key_t *this_key){
	record_t l, *p = NULL;
	record_t *r = NULL;

	memset(&l, 0, sizeof(record_t)); /* zero fill! */
	l.key = *this_key;
	HASH_FIND(hh, records, &l.key, sizeof(record_key_t), p);
	if(p==NULL){
		printf("new connection\n");
		r = (record_t*)malloc( sizeof(record_t) );
		if(!r) printf("Out of mem\n");
		memset(r, 0, sizeof(record_t)); /* zero fill! */
		r->key = *this_key;
		HASH_ADD(hh, records, key, sizeof(record_key_t), r);
		HASH_FIND(hh, records, &l.key, sizeof(record_key_t), p);
		if(r != p) printf("ERR hashing ptr\n");
	}
	if(!p) printf("ERR hashing\n");
	return p;
}


int main(int argc, char *argv[])
{
	char *device;
	int add_cctrack_rule = 1; // set to 0 to disable cctrack kernel plugin

	int ret = 0;
	u_char *buffer; // pointer in the ring to a received packet
	struct pfring_pkthdr hdr;

	char ipbuff1[sizeof("000.000.000.000")];
	char ipbuff2[sizeof("000.000.000.000")];

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

	// Device Initialization
	ring_ptr = init_ring(device, add_cctrack_rule);
	assert(ring_ptr != NULL);


	// Set signal handlers
	signal(SIGINT, terminate);
	for(;;) /* infinite loop */
	{
		ret = pfring_recv(ring_ptr,
				&buffer /* always supply valid pointer*/,
				0 /* buffer length*/,
				&hdr /* don't use packet header but NULL will seg fault here */,
				1 /* wait for incoming packet */);
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

				//printf("packet %s -> %s: ", ipbuff1, ipbuff2);
				{//ugly hack
				unsigned int h_limit;
				int h_cond;

				memcpy(&h_cond, &hdr.extended_hdr.parsed_pkt.dmac, sizeof(h_cond));
				memcpy(&h_limit, &hdr.extended_hdr.parsed_pkt.smac, sizeof(h_limit));
				printf("packet %s:%d -> %s:%d: bytes_sf: %u %s\n", ipbuff1,hdr.extended_hdr.parsed_pkt.l4_src_port, ipbuff2,
						hdr.extended_hdr.parsed_pkt.l4_dst_port, h_limit, h_cond ? "last" : "cont");
				if(!(h_cond == 1 || h_cond == 0)){
					puts("hdr.extended_hdr.parsed_pkt.dmac err");
				}
				}

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

				con_ht = getConnection(&con_key);

				/* l4 header + payload */
				con_ht->bytes_sampled +=
						hdr.caplen - hdr.extended_hdr.parsed_pkt.offset.l4_offset;
			}else{
				printf("packet ip version %d\n",
						hdr.extended_hdr.parsed_pkt.ip_version);
			}
		}
	}

}

void terminate(int signal)
{
	record_t *s;
	struct in_addr ip_src;
	struct in_addr ip_dst;
	char ipbuff1[sizeof("000.000.000.000")];
	char ipbuff2[sizeof("000.000.000.000")];

	// Device Termination
	pfring_close(ring_ptr);
	printf("\nSuccessfully closed device.\n");


	for(s=records; s != NULL; s=s->hh.next) {
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

	exit(0);
}
