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

// #define RING_DEBUG

/* ********************************* */

#include "pfring_mod.h"

#ifdef HAVE_DAG
#include "pfring_mod_dag.h"
#endif

#ifdef HAVE_DNA
#include "pfring_mod_dna.h"
#endif

#ifdef HAVE_VIRTUAL
#include "pfring_mod_virtual.h"
#endif

static pfring_module_info pfring_module_list[] = {
#ifdef HAVE_VIRTUAL
  { /* vPF_RING (guest-side) */
    .name = "host",
    .open = pfring_virtual_open,
  },
#endif
#ifdef HAVE_DAG
  {
    .name = "dag",
    .open = pfring_dag_open,
  },
#endif
#ifdef HAVE_DNA
  {
    .name = "dna",
    .open = pfring_dna_open,
  },
#endif
  {0}
};

/* **************************************************** */

pfring* pfring_open(char *device_name, u_int8_t promisc,
		    u_int32_t caplen, u_int8_t _reentrant) {
  int i = -1;
  int mod_found = 0;
  int ret;
  char *str;
  pfring *ring;
  
#ifdef RING_DEBUG
  printf("[PF_RING] Attempting to pfring_open(%s)\n", device_name);
#endif

  ring = (pfring*)malloc(sizeof(pfring));
  if(ring == NULL)
    return NULL;
  
  memset(ring, 0, sizeof(pfring));

  ring->promisc     = promisc;
  ring->caplen      = caplen;
  ring->reentrant   = _reentrant;
  ring->direction   = rx_and_tx_direction;

#ifdef RING_DEBUG
  printf("pfring_open: device_name=%s\n", device_name);
#endif
  /* modules */

  if(device_name) {
    ret = -1;
    ring->device_name = NULL;

#ifdef HAVE_DNA
    /*
      Check if this is a DNA adapter and for some
      reason the user forgot to add dna:ethX
    */
    if(strcmp(device_name, "any")
       && strcmp(device_name, "lo")
       && strncmp(device_name, "dna:", 4)) {
      ring->device_name = strdup(device_name);
      ret = pfring_dna_open(ring);     
    }    
#endif

    if(ret >= 0) {
      /* The DNA device exists */
      mod_found = 1;
    } else {
      if (ring->device_name != NULL) {
        free(ring->device_name);
        ring->device_name = NULL;
      }

      while (pfring_module_list[++i].name) {
	if(!(str = strstr(device_name, pfring_module_list[i].name))) continue;
	if(!(str = strchr(str, ':')))                                continue;
	if(!pfring_module_list[i].open)                              continue;

#ifdef RING_DEBUG
	printf("pfring_open: found module %s\n", pfring_module_list[i].name);
#endif

	mod_found = 1;
	ring->device_name = strdup(++str);
	ret = pfring_module_list[i].open(ring);
	break;
      }
    }
  }

  /* default */
  if(!mod_found) {
    ring->device_name = strdup(device_name ? device_name : "any");

    ret = pfring_mod_open(ring);
  }

  if(ret < 0) {
    if(ring->device_name) free(ring->device_name);
    free(ring);
    return NULL;
  }

  if(ring->reentrant)
    pthread_spin_init(&ring->spinlock, PTHREAD_PROCESS_PRIVATE);

  ring->initialized = 1;

#ifdef RING_DEBUG
  printf("[PF_RING] Successfully open pfring_open(%s)\n", device_name);
#endif
  return ring;
}

/* **************************************************** */

pfring* pfring_open_consumer(char *device_name, u_int8_t promisc,
			     u_int32_t caplen, u_int8_t _reentrant,
			     u_int8_t consumer_plugin_id,
			     char* consumer_data, u_int consumer_data_len) {
  pfring *ring = pfring_open(device_name, promisc, caplen, _reentrant);
  
  if(ring) {
    if(consumer_plugin_id > 0) {
      int rc;

      ring->kernel_packet_consumer = consumer_plugin_id;
      rc = pfring_set_packet_consumer_mode(ring, consumer_plugin_id,
					   consumer_data, consumer_data_len);
      if(rc < 0) {
	pfring_close(ring);
	return(NULL);
      }
    }
  }

  return ring;
}

/* **************************************************** */

u_int8_t pfring_open_multichannel(char *device_name, u_int8_t promisc,
				  u_int32_t caplen, u_int8_t _reentrant,
				  pfring* ring[MAX_NUM_RX_CHANNELS]) {
  u_int8_t num_channels, i, num = 0;
  char *at;
  char base_device_name[32];

  snprintf(base_device_name, sizeof(base_device_name), "%s", device_name);
  at = strchr(base_device_name, '@');
  if(at != NULL)
    at[0] = '\0';

  /* Count how many RX channel the specified device supports */
  ring[0] = pfring_open(base_device_name, promisc, caplen, _reentrant);

  if(ring[0] == NULL)
    return(0);
  else
    num_channels = pfring_get_num_rx_channels(ring[0]);

  pfring_close(ring[0]);

  /* Now do the real job */
  for(i=0; i<num_channels; i++) {
    char dev[32];

    snprintf(dev, sizeof(dev), "%s@%d", base_device_name, i);
    ring[i] = pfring_open(dev, promisc, caplen, _reentrant);

    if(ring[i] == NULL)
      return(num);
    else
      num++;
  }

  return(num);
}

/* **************************************************** */

void pfring_close(pfring *ring) {
  if(!ring)
    return;

  pfring_shutdown(ring);

  if(ring->close)
    ring->close(ring);
 
  if(ring->reentrant)
    pthread_spin_destroy(&ring->spinlock);

  free(ring->device_name);
  free(ring);
}

/* **************************************************** */

void pfring_shutdown(pfring *ring) {
  if(!ring)
    return;

  ring->is_shutting_down = ring->break_recv_loop = 1;
}

/* **************************************************** */

void pfring_config(u_short cpu_percentage) {
  static u_int pfring_initialized = 0;

  if(!pfring_initialized) {
    struct sched_param schedparam;

    /*if(cpu_percentage >= 50) mlockall(MCL_CURRENT|MCL_FUTURE); */

    pfring_initialized = 1;
    schedparam.sched_priority = cpu_percentage;
    if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
      printf("error while setting the scheduler, errno=%i\n", errno);
      exit(1);
    }
  }
}

/* **************************************************** */

int pfring_loop(pfring *ring, pfringProcesssPacket looper, const u_char *user_bytes) {
  u_char *buffer = NULL;
  struct pfring_pkthdr hdr;
  int rc = 0;

  if(!ring)
    return -1;

  ring->break_recv_loop = 0;

  while(!ring->break_recv_loop) {
    rc = pfring_recv(ring, &buffer, 0, &hdr, 1);
    if(rc < 0)
      break;
    else if(rc > 0)
      looper(&hdr, buffer, user_bytes);
  }

  return(rc);
}

/* **************************************************** */

void pfring_breakloop(pfring *ring) {
  if(!ring)
    return;

  ring->break_recv_loop = 1;
}

/* **************************************************** */
/*                Module-specific functions             */
/* **************************************************** */

int pfring_stats(pfring *ring, pfring_stat *stats) {
  if(ring && ring->stats)
    return ring->stats(ring, stats);

  return -1;
}

/* **************************************************** */

int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		struct pfring_pkthdr *hdr,
		u_int8_t wait_for_incoming_packet) {
  if(ring && ring->enabled && ring->recv && (ring->direction != tx_only_direction))
    return ring->recv(ring, buffer, buffer_len, hdr, wait_for_incoming_packet);

  return -1;
}

/* **************************************************** */

int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  if(ring && ring->set_poll_watermark)
    return ring->set_poll_watermark(ring, watermark);

  return(-1);
}

/* **************************************************** */

int pfring_set_poll_duration(pfring *ring, u_int duration) {
  if(ring && ring->set_poll_duration)
    return ring->set_poll_duration(ring, duration);

  return -1;
}

/* **************************************************** */

int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  if(ring && ring->add_hw_rule)
    return ring->add_hw_rule(ring, rule);

  return -1;
}

/* **************************************************** */

int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  if(ring && ring->remove_hw_rule)
    return ring->remove_hw_rule(ring, rule_id);

  return -1;
}

/* **************************************************** */

int pfring_set_channel_id(pfring *ring, u_int32_t channel_id) {
  if(ring && ring->set_channel_id)
    return ring->set_channel_id(ring, channel_id);

  return -1;
}

/* **************************************************** */

int pfring_set_application_name(pfring *ring, char *name) {
  if(ring && ring->set_application_name)
    return ring->set_application_name(ring, name);

  return -1;
}

/* **************************************************** */

int pfring_bind(pfring *ring, char *device_name) { 
  if(ring && ring->bind)
    return ring->bind(ring, device_name);

  return -1;
}

/* **************************************************** */

int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  if(ring && ring->enabled && ring->send && (ring->direction != rx_only_direction))
    return ring->send(ring, pkt, pkt_len, flush_packet);

  return -1;
}

/* **************************************************** */

u_int8_t pfring_get_num_rx_channels(pfring *ring) {
  if(ring && ring->get_num_rx_channels)
    return ring->get_num_rx_channels(ring);

  return 1;
}

/* **************************************************** */

int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  if(ring && ring->set_sampling_rate)
    return ring->set_sampling_rate(ring, rate);

  return(-1);
}

/* **************************************************** */

int pfring_get_selectable_fd(pfring *ring) {
  if(ring && ring->get_selectable_fd)
    return ring->get_selectable_fd(ring);

  return -1;
}

/* **************************************************** */

int pfring_set_direction(pfring *ring, packet_direction direction) {
  if(ring && ring->set_direction) {
    int rc = ring->set_direction(ring, direction);

    if(rc == 0)
      ring->direction = direction;

    return(rc);
  }

  return -1;
}

/* **************************************************** */

int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type) {
  if(ring && ring->set_cluster)
    return ring->set_cluster(ring, clusterId, the_type);

  return -1;
}

/* **************************************************** */

int pfring_remove_from_cluster(pfring *ring) {
  if(ring && ring->remove_from_cluster)
    return ring->remove_from_cluster(ring);

  return -1;
}

/* **************************************************** */

int pfring_set_master_id(pfring *ring, u_int32_t master_id) {
  if(ring && ring->set_master_id)
    return ring->set_master_id(ring, master_id);

  return -1;
}

/* **************************************************** */

int pfring_set_master(pfring *ring, pfring *master) {
  if(ring && ring->set_master)
    return ring->set_master(ring, master);

  return -1;
}

/* **************************************************** */

u_int16_t pfring_get_ring_id(pfring *ring) {
  if(ring && ring->get_ring_id)
    return ring->get_ring_id(ring);

  return -1;
}

/* **************************************************** */

u_int32_t pfring_get_num_queued_pkts(pfring *ring) {
  if(ring && ring->get_num_queued_pkts)
    return ring->get_num_queued_pkts(ring);

  return 0;
}

/* **************************************************** */

u_int8_t pfring_get_packet_consumer_mode(pfring *ring) {
  if(ring && ring->get_packet_consumer_mode)
    return ring->get_packet_consumer_mode(ring);

  return -1;
}

/* **************************************************** */

int pfring_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id, 
				    char *plugin_data, u_int plugin_data_len) {
  if(ring && ring->set_packet_consumer_mode)
    return ring->set_packet_consumer_mode(ring, plugin_id, plugin_data, plugin_data_len);

  return -1;
}

/* **************************************************** */

int pfring_get_hash_filtering_rule_stats(pfring *ring, hash_filtering_rule* rule, 
					 char* stats, u_int *stats_len) {
  if(ring && ring->get_hash_filtering_rule_stats)
    return ring->get_hash_filtering_rule_stats(ring, rule, stats, stats_len);

  return -1;
}

/* **************************************************** */

int pfring_handle_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add, 
				      u_char add_rule) {
  if(ring && ring->handle_hash_filtering_rule)
    return ring->handle_hash_filtering_rule(ring, rule_to_add, add_rule);

  return -1;
}

/* **************************************************** */

int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec) {
  if(ring && ring->purge_idle_hash_rules)
    return ring->purge_idle_hash_rules(ring, inactivity_sec);

  return -1;
}

/* **************************************************** */

int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  if(ring && ring->add_filtering_rule)
    return ring->add_filtering_rule(ring, rule_to_add);

  return -1;
}

/* **************************************************** */

int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  if(ring && ring->remove_filtering_rule)
    return ring->remove_filtering_rule(ring, rule_id);

  return -1;
}

/* **************************************************** */

int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id, 
				    char* stats, u_int *stats_len) {
  if(ring && ring->get_filtering_rule_stats)
    return ring->get_filtering_rule_stats(ring, rule_id, stats, stats_len);

  return -1;
}

/* **************************************************** */

int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy) {
  if(ring && ring->toggle_filtering_policy)
    return ring->toggle_filtering_policy(ring, rules_default_accept_policy);

  return -1;
}

/* **************************************************** */

int pfring_enable_rss_rehash(pfring *ring) {
  if(ring && ring->enable_rss_rehash)
    return ring->enable_rss_rehash(ring);

  return -1;
}

/* **************************************************** */

int pfring_poll(pfring *ring, u_int wait_duration) {
  if(ring && ring->poll)
    return ring->poll(ring, wait_duration);

  return -1;
}

/* **************************************************** */

int pfring_version(pfring *ring, u_int32_t *version) {
  if(ring && ring->version)
    return ring->version(ring, version);

  *version = RING_VERSION_NUM;
  return 0;/*-1*/;
}

/* **************************************************** */

int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  if(ring && ring->get_bound_device_address)
    return ring->get_bound_device_address(ring, mac_address);

  return -1;
}

/* **************************************************** */

u_int16_t pfring_get_slot_header_len(pfring *ring) {
  if(ring && ring->get_slot_header_len)
    return ring->get_slot_header_len(ring);

  return -1;
}

/* **************************************************** */

int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info) {
  if(ring && ring->set_virtual_device)
    return ring->set_virtual_device(ring, info);

  return -1;
}

/* **************************************************** */

int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len) {
  if(ring && ring->loopback_test)
    return ring->loopback_test(ring, buffer, buffer_len, test_len);

  return -1;
}

/* **************************************************** */

int pfring_enable_ring(pfring *ring) {
  if(ring && ring->enable_ring) {
    int rc;
    
    if(ring->enabled) return(0);
    rc = ring->enable_ring(ring);
    if(rc == 0) ring->enabled = 1;

    return rc;
  }

  return -1;
}

/* **************************************************** */

int pfring_disable_ring(pfring *ring) {
  if(ring && ring->disable_ring) {
    int rc;

    if(!ring->enabled) return(0);
    rc = ring->disable_ring(ring);
    if(rc == 0) ring->enabled = 0;

    return rc;
  }

  return -1;
}

/* **************************************************** */

