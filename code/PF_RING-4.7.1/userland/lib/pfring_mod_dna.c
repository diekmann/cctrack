/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 * This code includes contributions courtesy of
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 *
 */

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_utils.h"
#include "pfring_mod_dna.h"

//#define RING_DEBUG

/* ******************************* */

static int pfring_map_dna_device(pfring *ring,
				 dna_device_operation operation,
				 char *device_name) {
  dna_device_mapping mapping;

  if(ring->last_dna_operation == operation) {
    fprintf(stderr, "%s(): operation (%s) already performed\n",
	    __FUNCTION__, operation == remove_device_mapping ?
	    "remove_device_mapping" : "add_device_mapping");
    return (-1);
  } else
    ring->last_dna_operation = operation;

  mapping.operation = operation;
  snprintf(mapping.device_name, sizeof(mapping.device_name),
	   "%s", device_name);
  mapping.channel_id = ring->dna_dev.channel_id;

  return(ring ? setsockopt(ring->fd, 0, SO_MAP_DNA_DEVICE,
			   &mapping, sizeof(mapping)): -1);
}

/* **************************************************** */

void pfring_dna_close(pfring *ring) {

  if(ring->dna_term)
    ring->dna_term(ring);

  if(ring->dna_dev.rx_packet_memory != 0)
    munmap((void*)ring->dna_dev.rx_packet_memory,
	     ring->dna_dev.packet_memory_tot_len);

  if(ring->dna_dev.rx_descr_packet_memory != NULL)
    munmap(ring->dna_dev.rx_descr_packet_memory, ring->dna_dev.descr_packet_memory_tot_len);
  
  if(ring->dna_dev.tx_packet_memory != 0)
    munmap((void*)ring->dna_dev.tx_packet_memory,
	     ring->dna_dev.packet_memory_tot_len);

  if(ring->dna_dev.tx_descr_packet_memory != NULL)
    munmap(ring->dna_dev.tx_descr_packet_memory, ring->dna_dev.descr_packet_memory_tot_len);

  if(ring->dna_dev.phys_card_memory != NULL)
    munmap(ring->dna_dev.phys_card_memory,
           ring->dna_dev.phys_card_memory_len);

  pfring_map_dna_device(ring, remove_device_mapping, "");

  if(ring->clear_promisc)
    set_if_promisc(ring->device_name, 0);

  close(ring->fd);
}

/* **************************************************** */

int pfring_dna_stats(pfring *ring, pfring_stat *stats) {
  stats->recv = ring->tot_dna_read_pkts, stats->drop = 0;
  return(0);
}

/* **************************************************** */

int pfring_dna_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		    struct pfring_pkthdr *hdr,
		    u_int8_t wait_for_incoming_packet) {
  u_char *pkt = NULL;
  int8_t status = 1;

  if(ring->is_shutting_down) return(-1);

  ring->break_recv_loop = 0;
  if(ring->reentrant) pthread_spin_lock(&ring->spinlock);

  redo_pfring_recv:
    if(ring->is_shutting_down || ring->break_recv_loop) {
      if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);
      return(-1);
    }

    pkt = ring->dna_next_packet(ring, buffer, buffer_len, hdr);

    if(pkt && (hdr->len > 0)) {
      /* Set the (1) below to (0) for enabling packet parsing for DNA devices */
      if(0)
	hdr->extended_hdr.parsed_header_len = 0;
      else if(buffer_len > 0)
	parse_pkt(*buffer, hdr);

      if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);
      return(1);
    }

    if(wait_for_incoming_packet) {
      status = ring->dna_check_packet_to_read(ring, wait_for_incoming_packet);
    }

    if(status > 0)
      goto redo_pfring_recv;

    if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);
    return(0);
 }

/* ******************************* */

static int pfring_get_mapped_dna_device(pfring *ring, dna_device *dev) {
  socklen_t len = sizeof(dna_device);

  if(dev == NULL)
    return(-1);
  else
    return(getsockopt(ring->fd, 0, SO_GET_MAPPED_DNA_DEVICE, dev, &len));
}

/* **************************************************** */

#ifdef DEBUG

static void pfring_dump_dna_stats(pfring* ring) {
  dna_dump_stats(ring);
}

#endif

/* **************************************************** */

int pfring_dna_open(pfring *ring) {
  int   channel_id = 0;
  int   rc;
  char *at;

  ring->close = pfring_dna_close;
  ring->stats = pfring_dna_stats;
  ring->recv  = pfring_dna_recv;
  ring->set_poll_watermark = pfring_mod_set_poll_watermark;
  ring->set_poll_duration = pfring_mod_set_poll_duration;
  ring->add_hw_rule = pfring_mod_add_hw_rule;
  ring->remove_hw_rule = pfring_mod_remove_hw_rule;
  ring->set_channel_id = pfring_mod_set_channel_id;
  ring->set_application_name = pfring_mod_set_application_name;
  ring->bind = pfring_mod_bind;
  ring->send = NULL; /* Set by the dna library */
  ring->get_num_rx_channels = pfring_mod_get_num_rx_channels;
  ring->set_sampling_rate = pfring_mod_set_sampling_rate;
  ring->get_selectable_fd = pfring_mod_get_selectable_fd;
  ring->set_direction = pfring_mod_set_direction;
  ring->set_cluster = pfring_mod_set_cluster;
  ring->remove_from_cluster = pfring_mod_remove_from_cluster;
  ring->set_master_id = pfring_mod_set_master_id;
  ring->set_master = pfring_mod_set_master;
  ring->get_ring_id = pfring_mod_get_ring_id;
  ring->get_num_queued_pkts = pfring_mod_get_num_queued_pkts;
  ring->get_packet_consumer_mode = pfring_mod_get_packet_consumer_mode;
  ring->set_packet_consumer_mode = pfring_mod_set_packet_consumer_mode;
  ring->get_hash_filtering_rule_stats = pfring_mod_get_hash_filtering_rule_stats;
  ring->handle_hash_filtering_rule = pfring_mod_handle_hash_filtering_rule;
  ring->purge_idle_hash_rules = pfring_mod_purge_idle_hash_rules;
  ring->add_filtering_rule = pfring_mod_add_filtering_rule;
  ring->remove_filtering_rule = pfring_mod_remove_filtering_rule;
  ring->get_filtering_rule_stats = pfring_mod_get_filtering_rule_stats;
  ring->toggle_filtering_policy = pfring_mod_toggle_filtering_policy;
  ring->enable_rss_rehash = pfring_mod_enable_rss_rehash;
  ring->poll = pfring_mod_poll;
  ring->version = pfring_mod_version;
  ring->get_bound_device_address = pfring_mod_get_bound_device_address;
  ring->get_slot_header_len = pfring_mod_get_slot_header_len;
  ring->set_virtual_device = pfring_mod_set_virtual_device;
  ring->loopback_test = pfring_mod_loopback_test;
  ring->enable_ring = pfring_mod_enable_ring;
  ring->disable_ring = pfring_mod_disable_ring;

  ring->last_dna_operation = remove_device_mapping;
  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

#ifdef DEBUG
  printf("Open RING [fd=%d]\n", ring->fd);
#endif

  if(ring->fd < 0)
    return -1;

  at = strchr(ring->device_name, '@');
  if(at != NULL) {
    at[0] = '\0';

    /* 
       Syntax
       ethX@1      channel 1
    */
    
    channel_id = atoi(&at[1]);
  }

  ring->dna_dev.channel_id = channel_id;

  rc = pfring_map_dna_device(ring, add_device_mapping, ring->device_name);

  if(rc < 0) {
#if 0
    printf("pfring_map_dna_device() failed [rc=%d]: device already in use, channel not existing or non-DNA driver?\n", rc);
    printf("Make sure that you load the DNA-driver *after* you loaded the PF_RING kernel module\n");
#endif
    return -1;
  }

  rc = pfring_get_mapped_dna_device(ring, &ring->dna_dev);

  if (rc < 0) {
      printf("pfring_get_mapped_dna_device() failed [rc=%d]\n", rc);
      pfring_map_dna_device(ring, remove_device_mapping, ring->device_name);
      close(ring->fd);
      return -1;
  }

#ifdef DEBUG
  printf("[num_slots=%d][slot_len=%d][tot_mem_len=%d]\n",
	 ring->dna_dev.packet_memory_num_slots,
	 ring->dna_dev.packet_memory_slot_len,
	 ring->dna_dev.packet_memory_tot_len);
  printf("[memory_num_slots=%d][memory_slot_len=%d]"
	 "[memory_tot_len=%d]\n",
	 ring->dna_dev.descr_packet_memory_num_slots,
	 ring->dna_dev.descr_packet_memory_slot_len,
	 ring->dna_dev.descr_packet_memory_tot_len);
#endif

  ring->dna_mapped_device = 1;

  /* ***************************************** */

  if (ring->dna_dev.packet_memory_tot_len > 0){
    ring->dna_dev.rx_packet_memory =
	(unsigned long)mmap(NULL, ring->dna_dev.packet_memory_tot_len,
			    PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 1*getpagesize());

    if(ring->dna_dev.rx_packet_memory == (unsigned long)MAP_FAILED) {
      printf("mmap(1) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if (ring->dna_dev.descr_packet_memory_tot_len > 0){
    ring->dna_dev.rx_descr_packet_memory =
        (void*)mmap(NULL, ring->dna_dev.descr_packet_memory_tot_len,
		    PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 2*getpagesize());

    if(ring->dna_dev.rx_descr_packet_memory == MAP_FAILED) {
      printf("mmap(2) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if (ring->dna_dev.phys_card_memory_len > 0) {
    /* some DNA drivers do not use this memory */
    ring->dna_dev.phys_card_memory =
	  (void*)mmap(NULL, ring->dna_dev.phys_card_memory_len,
		      PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 3*getpagesize());

    if(ring->dna_dev.phys_card_memory == MAP_FAILED) {
      printf("mmap(3) failed");
      close(ring->fd);
      return -1;
    }
  }


  /* ***************************************** */

  if (ring->dna_dev.packet_memory_tot_len > 0){
    ring->dna_dev.tx_packet_memory =
        (unsigned long)mmap(NULL, ring->dna_dev.packet_memory_tot_len,
                            PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 4*getpagesize());

    if(ring->dna_dev.tx_packet_memory == (unsigned long)MAP_FAILED) {
      printf("mmap(4) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if (ring->dna_dev.descr_packet_memory_tot_len > 0){
    ring->dna_dev.tx_descr_packet_memory =
        (void*)mmap(NULL, ring->dna_dev.descr_packet_memory_tot_len,
                    PROT_READ|PROT_WRITE, MAP_SHARED, ring->fd, 5*getpagesize());

    if(ring->dna_dev.tx_descr_packet_memory == MAP_FAILED) {
      printf("mmap(5) failed");
      close(ring->fd);
      return -1;
    }
  }

  /* ***************************************** */

  if(ring->promisc) {
    if(set_if_promisc(ring->device_name, 1) == 0)
      ring->clear_promisc = 1;
  }

  if(dna_init(ring, sizeof(pfring)) == -1) {
    printf("dna_init() failed\n");
    close(ring->fd);
    return -1;
  }

#ifdef DEBUG
  pfring_dump_dna_stats(ring);
#endif

  return 0;
}

/* *********************************** */

