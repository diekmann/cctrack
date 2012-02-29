/*
 * test_cctrack_dynamic.c
 *
 *  Created on: Aug 18, 2011
 *      Author: corny
 */

/* this is for testing purposes only, it leaks memory like hell!  */

#include <assert.h>
#include <signal.h>
#include "pfring.h"
#include "uthash.h"
#include "../../kernel/plugins/corny_conntrack_plugin.h"
#include "util.h"

#include <time.h>


#define ERROR -1

// Pointer to pfring struct
pfring* ring_ptr;

void terminate(int signal);
int main(int argc, char *argv[]);




void print_stats_ring_generic() {
	pfring_stat pfringStat;

	if(pfring_stats(ring_ptr, &pfringStat) >= 0)
		fprintf(stderr, "=========================\n"
				"Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
				"Total Pkts=%u/Dropped=%.1f %%\n",
				(unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
				(unsigned int)(pfringStat.recv-pfringStat.drop),
				pfringStat.recv == 0 ? 0 : (double)(pfringStat.drop*100)/(double)pfringStat.recv);


	fprintf(stderr, "=========================\n");
}


//void print_stats_cctrack() {
//	char *stats = NULL;
//	uint stats_len = sizeof(stats);
//
//	stats = malloc(sizeof(struct cctrack_stats));
//	if(stats == NULL){
//		printf("stats: out of mem\n");
//		return;
//	}
//
//	BROKEN
//	if(pfring_get_filtering_rule_stats(ring_ptr, CCTRACK_RULE_ID, stats, &stats_len) == stats_len){
//		fprintf(stderr, "=========================\n");
//	}else{
//		fprintf(stderr, "pfring_get_filtering_rule_stats error\n");
//	}
//
//
//	fprintf(stderr, "=========================\n");
//
//	free(stats);
//}



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

				ip_src.s_addr = endian_swap(hdr.extended_hdr.parsed_pkt.ip_src.v4);
				ip_dst.s_addr = endian_swap(hdr.extended_hdr.parsed_pkt.ip_dst.v4);

				strcpy(ipbuff1, inet_ntoa(ip_src));
				strcpy(ipbuff2, inet_ntoa(ip_dst));

				printf("packet %s -> %s: ", ipbuff1, ipbuff2);

				print_packet_ascii(&hdr, buffer);
				msleep(10);

			}else{
				printf("packet ip version %d\n",
						hdr.extended_hdr.parsed_pkt.ip_version);
			}
		}
	}

}

void terminate(int signal)
{
	// Device Termination
	pfring_close(ring_ptr);
	printf("\nSuccessfully closed device.\n");

	exit(0);
}
