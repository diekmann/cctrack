/*
 * util.h
 *
 *  Created on: Aug 18, 2011
 *      Author: corny
 */

#ifndef UTIL_H_
#define UTIL_H_



/* from http://cc.byexamples.com/2007/05/25/nanosleep-is-better-than-sleep-and-usleep/ */
void __nsleep(const struct timespec *req, struct timespec *rem)
{
	struct timespec temp_rem;
	if(nanosleep(req,rem)==-1){
		__nsleep(rem,&temp_rem);
	}
}

int msleep(unsigned long milisec)
{
	struct timespec req={0},rem={0};
	time_t sec=(int)(milisec/1000);
	milisec=milisec-(sec*1000);
	req.tv_sec=sec;
	req.tv_nsec=milisec*1000000L;
	__nsleep(&req,&rem);
	return 1;
}




uint32_t endian_swap(uint32_t x)
{
	x = (x>>24) |
			((x<<8) & 0x00FF0000) |
			((x>>8) & 0x0000FF00) |
			(x<<24);
	return x;
}


#define PROMISC_MODE 1
#define CAPTURE_LENGTH 3200000 //TODO: What is a good max. catpure length?
#define REENTRANT_MODE 0

#define CCTRACK_RULE_ID 8

pfring *init_ring(char *device, int add_cctrack_rule){
	pfring* ring_ptr;


	ring_ptr = pfring_open(device, PROMISC_MODE, CAPTURE_LENGTH, REENTRANT_MODE);


	// Check if opening the device was successful
	if (ring_ptr == NULL)
	{
		printf("Error: Unable to open device %s for pfring!\n", device);
		exit(-1);
	}
	else {
		printf("Successfully opened device %s for pfring.\n", device);
	}


	///////////////////////////
	// Create filtering rule //
	///////////////////////////
	filtering_rule rule;

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

	// Enable the ring
	if (pfring_enable_ring(ring_ptr) != 0)
	{
		printf("Error: Unable to enable ring!\n");
		exit(-1);
	}
	else {
		printf("Successfully enabled ring.\n");
	}

	return ring_ptr;
}


void print_packet_ascii(struct pfring_pkthdr *hdr, u_char *buffer){
	int i;

	/* this prints as ascii */
	for(i=hdr->extended_hdr.parsed_header_len+hdr->extended_hdr.parsed_pkt.offset.payload_offset;
			i<hdr->extended_hdr.parsed_header_len+hdr->caplen; ++i)
	{
		if ( ( buffer[i] < 32 ) || ( buffer[i] > 126 ) ) {
			printf("%c", '.');
		}else{
			printf("%c", buffer[i]);
		}
	}
	printf("\n");
}


void print_packet_dbg(struct pfring_pkthdr *hdr, u_char *buffer){
	int i;

	/*This dumps the packet including its header*/
	for(i=0; i<hdr->extended_hdr.parsed_header_len+hdr->caplen; ++i){
		printf("%02x ", buffer[i]);
	}

}



void print_packet_payload(struct pfring_pkthdr *hdr, u_char *buffer){
	int i;

	/* this dumps the payload */
	for(i=hdr->extended_hdr.parsed_header_len+hdr->extended_hdr.parsed_pkt.offset.payload_offset;
			i<hdr->extended_hdr.parsed_header_len+hdr->caplen; ++i)
	{
		printf("%02x ", buffer[i]);
	}

}


#endif /* UTIL_H_ */
