/*
 *
 * (C) 2005-10 - Luca Deri <deri@ntop.org>
 *
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
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define MAX_NUM_THREADS        64
#define DEFAULT_DEVICE     "eth0"
pfring  *pd;
int verbose = 0, num_threads = 1;
pfring_stat pfringStats;
pthread_rwlock_t statsLock;

static struct timeval startTime;
unsigned long long numPkts[MAX_NUM_THREADS] = { 0 }, numBytes[MAX_NUM_THREADS] = { 0 };
u_int8_t wait_for_packet = 1, dna_mode = 0, do_shutdown = 0;

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(pfring_stats(pd, &pfringStat) >= 0) {
    double thpt;
    int i;
    unsigned long long nBytes = 0, nPkts = 0;

    for(i=0; i < num_threads; i++) {
      nBytes += numBytes[i];
      nPkts += numPkts[i];
    }

    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
	    (unsigned int)(pfringStat.recv+pfringStat.drop),
	    pfringStat.recv == 0 ? 0 :
	    (double)(pfringStat.drop*100)/(double)(pfringStat.recv+pfringStat.drop));
    fprintf(stderr, "%llu pkts - %llu bytes", nPkts, nBytes);

    if(print_all)
      fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n",
	      (double)(nPkts*1000)/deltaMillisec, thpt);
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = pfringStat.recv-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	      (long long unsigned int)diff,
	      deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)));
    }

    lastPkts = pfringStat.recv;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void add_rule(u_int add_rule) {
#if 0
  hash_filtering_rule rule;

  memset(&rule, 0, sizeof(hash_filtering_rule));
  /* 09:40:01.158112 IP 192.168.1.233.2736 > 192.168.99.1.25: Flags [P.], seq 1070303040:1070303070, ack 3485710921, win 65461, length 30 */
  rule.proto = 6, rule.rule_id = 10; rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
  rule.host4_peer_a = ntohl(inet_addr("192.168.1.233"));
  rule.host4_peer_b = ntohl(inet_addr("192.168.99.1"));

  if(pfring_handle_hash_filtering_rule(pd, &rule, add_rule) < 0)
    printf("pfring_add_hash_filtering_rule(1) failed\n");

  rule.proto = 6, rule.rule_id = 11; rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
  rule.host4_peer_a = ntohl(inet_addr("192.168.1.233"));
  rule.host4_peer_b = ntohl(inet_addr("192.168.99.1"));

  if(pfring_handle_hash_filtering_rule(pd, &rule, add_rule) < 0)
    printf("pfring_add_hash_filtering_rule(2) failed\n");
#else
  filtering_rule rule;

  memset(&rule, 0, sizeof(rule));

  rule.rule_id = 5;
  rule.rule_action = forward_packet_and_stop_rule_evaluation;
  rule.core_fields.port_low = 80, rule.core_fields.port_high = 80;

  if(pfring_add_filtering_rule(pd, &rule) < 0)
    printf("pfring_add_hash_filtering_rule(2) failed\n");
  else
    printf("Rule added successfully...\n");
#endif
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(0) {
    add_rule(0);
    printf("Removing filter\n");
  }

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  if(num_threads == 1)
    pfring_close(pd);

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p, long threadId) {
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s = (h->ts.tv_sec + thiszone) % 86400;
    u_int nsec = h->extended_hdr.timestamp_ns % 1000;

    printf("%02d:%02d:%02d.%06u%03u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec, nsec);

#if 0
    for(i=0; i<32; i++)
      printf("%02X ", p[i]);

    printf("\n");
#endif

    if(h->extended_hdr.parsed_header_len > 0) {
      printf("[eth_type=0x%04X]", h->extended_hdr.parsed_pkt.eth_type);
      printf("[l3_proto=%u]", (unsigned int)h->extended_hdr.parsed_pkt.l3_proto);

      printf("[%s:%d -> ", (h->extended_hdr.parsed_pkt.eth_type == 0x86DD) ?
	     in6toa(h->extended_hdr.parsed_pkt.ipv6_src) : intoa(h->extended_hdr.parsed_pkt.ipv4_src),
	     h->extended_hdr.parsed_pkt.l4_src_port);
      printf("%s:%d] ", (h->extended_hdr.parsed_pkt.eth_type == 0x86DD) ?
	     in6toa(h->extended_hdr.parsed_pkt.ipv6_dst) : intoa(h->extended_hdr.parsed_pkt.ipv4_dst),
	     h->extended_hdr.parsed_pkt.l4_dst_port);

      printf("[%s -> %s] ",
	     etheraddr_string(h->extended_hdr.parsed_pkt.smac, buf1),
	     etheraddr_string(h->extended_hdr.parsed_pkt.dmac, buf2));
    }

    memcpy(&ehdr, p+h->extended_hdr.parsed_header_len, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);

    printf("[%s -> %s][eth_type=0x%04X] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2), eth_type);


    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }

    if(eth_type == 0x0800) {
      memcpy(&ip, p+h->extended_hdr.parsed_header_len+sizeof(ehdr), sizeof(struct ip));
      printf("[%s]", proto2str(ip.ip_p));
      printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), h->extended_hdr.parsed_pkt.l4_src_port);
      printf("-> %s:%d] ", intoa(ntohl(ip.ip_dst.s_addr)), h->extended_hdr.parsed_pkt.l4_dst_port);

      printf("[tos=%d][tcp_seq_num=%u][caplen=%d][len=%d][parsed_header_len=%d]"
	     "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	     h->extended_hdr.parsed_pkt.ipv4_tos, h->extended_hdr.parsed_pkt.tcp.seq_num,
	     h->caplen, h->len, h->extended_hdr.parsed_header_len,
	     h->extended_hdr.parsed_pkt.offset.eth_offset,
	     h->extended_hdr.parsed_pkt.offset.l3_offset,
	     h->extended_hdr.parsed_pkt.offset.l4_offset,
	     h->extended_hdr.parsed_pkt.offset.payload_offset);

    } else {
      if(eth_type == 0x0806)
	printf("[ARP]");
      else
	printf("[eth_type=0x%04X]", eth_type);

      printf("[caplen=%d][len=%d][parsed_header_len=%d]"
	     "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	     h->caplen, h->len, h->extended_hdr.parsed_header_len,
	     h->extended_hdr.parsed_pkt.offset.eth_offset,
	     h->extended_hdr.parsed_pkt.offset.l3_offset,
	     h->extended_hdr.parsed_pkt.offset.l4_offset,
	     h->extended_hdr.parsed_pkt.offset.payload_offset);
    }
  }

  numPkts[threadId]++, numBytes[threadId] += h->len;
}

/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount_82599\n(C) 2011 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device@channel for channels\n");
  printf("-n <threads>    Number of polling threads (default %d)\n", num_threads);

  /* printf("-f <filter>     [pfring filter]\n"); */

  printf("-c <cluster id> cluster id\n");
  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-s <string>     String to search on packets\n");
  printf("-l <len>        Capture length\n");
  printf("-a              Active packet wait\n");
  printf("-v              Verbose\n");
}

/* *************************************** */

void* packet_consumer_thread(void* _id) {
  int s;
  long thread_id = (long)_id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_long core_id = thread_id % numCPU;

  if((num_threads > 1) && (numCPU > 1)) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      printf("Error while binding thread %ld to core %ld: errno=%i\n",
	     thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }

  while(1) {
    struct simple_stats {
      u_int64_t num_pkts, num_bytes;
    };

    u_char *buffer;
    struct simple_stats stats;
    struct pfring_pkthdr hdr;
    int rc;
    u_int len;

    if(do_shutdown) break;

    if(pfring_recv(pd, &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      dummyProcesssPacket(&hdr, buffer, thread_id);

#ifdef TEST_SEND
      buffer[0] = 0x99;
      buffer[1] = 0x98;
      buffer[2] = 0x97;
      pfring_send(pd, buffer, hdr.caplen);
#endif
    }

    if(0) {
      len = sizeof(stats);
      rc = pfring_get_filtering_rule_stats(pd, 5, (char*)&stats, &len);
      if(rc < 0)
	printf("pfring_get_filtering_rule_stats() failed [rc=%d]\n", rc);
      else {
	printf("[Pkts=%u][Bytes=%u]\n",
	       (unsigned int)stats.num_pkts,
	       (unsigned int)stats.num_bytes);
      }
    }
  }

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *string = NULL;
  int promisc, snaplen = DEFAULT_SNAPLEN, rc;
  u_int clusterId = 0;
  packet_direction direction = rx_and_tx_direction;
  u_int16_t watermark = 0;

#if 0
  struct sched_param schedparam;

  schedparam.sched_priority = 99;
  if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
    printf("error while setting the scheduler, errno=%i\n", errno);
    exit(1);
  }

  mlockall(MCL_CURRENT|MCL_FUTURE);

#undef TEST_PROCESSOR_AFFINITY
#ifdef TEST_PROCESSOR_AFFINITY
  {
    unsigned long new_mask = 1;
    unsigned int len = sizeof(new_mask);
    unsigned long cur_mask;
    pid_t p = 0; /* current process */
    int ret;

    ret = sched_getaffinity(p, len, NULL);
    printf(" sched_getaffinity = %d, len = %u\n", ret, len);

    ret = sched_getaffinity(p, len, &cur_mask);
    printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);

    ret = sched_setaffinity(p, len, &new_mask);
    printf(" sched_setaffinity = %d, new_mask = %08lx\n", ret, new_mask);

    ret = sched_getaffinity(p, len, &cur_mask);
    printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);
  }
#endif
#endif

  startTime.tv_sec = 0;
  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"hi:c:l:vs:ae:n:w:" /* "f:" */)) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction:
      case rx_only_direction:
      case tx_only_direction:
	direction = atoi(optarg);
	break;
      }
      break;
    case 'c':
      clusterId = atoi(optarg);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'n':
      num_threads = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
      /*
	case 'f':
	bpfFilter = strdup(optarg);
	break;
      */
    case 's':
      string = strdup(optarg);
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;
  if(num_threads > MAX_NUM_THREADS) num_threads = MAX_NUM_THREADS;

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  if(num_threads > 0)
    pthread_rwlock_init(&statsLock, NULL);

  pd = pfring_open(device, promisc,  snaplen, (num_threads > 1) ? 1 : 0);

  if(pd == NULL) {
    printf("pfring_open error\n");
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfcount_82599");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd));
  printf("# Polling threads:    %d\n", num_threads);

  if(clusterId > 0) {
    rc = pfring_set_cluster(pd, clusterId, cluster_round_robin);
    printf("pfring_set_cluster returned %d\n", rc);
  }

  if((rc = pfring_set_direction(pd, direction)) != 0)
    printf("pfring_set_direction returned [rc=%d][direction=%d]\n", rc, direction);

  if(watermark > 0) {
    if((rc = pfring_set_poll_watermark(pd, watermark)) != 0)
      printf("pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
  }


  if(0) {
    int rc, rule_id = 0;
    hw_filtering_rule rule;
    intel_82599_five_tuple_filter_hw_rule *ft_rule;

    printf("### FTFQ Rule Example ###\n");

    ft_rule = &rule.rule_family.five_tuple_rule;

    if(0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 17; /* udp */
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping UDP traffic\n", rule.rule_id);
    }

    if(0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6; /* tcp */
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic\n", rule.rule_id);
    }

    memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
    rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6, ft_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
    rc = pfring_add_hw_rule(pd, &rule);
    if(rc != 0)
      printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
    else
      printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic 192.168.30.207 -> *\n", rule.rule_id);

    memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
    rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6, ft_rule->d_addr = ntohl(inet_addr("192.168.30.207"));
    rc = pfring_add_hw_rule(pd, &rule);
    if(rc != 0)
      printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
    else
      printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic * -> 192.168.30.207\n", rule.rule_id);

    memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
    rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 0, ft_rule->d_addr = ntohl(inet_addr("192.168.30.207"));
    rc = pfring_add_hw_rule(pd, &rule);
    if(rc != 0)
      printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
    else
      printf("pfring_add_hw_rule(%d) succeeded: dropping non-TCP/UDP traffic * -> 192.168.30.207\n", rule.rule_id);
  }

  if(1) {
    int rc, rule_id = 0;
    hw_filtering_rule rule;
    intel_82599_perfect_filter_hw_rule *perfect_rule;

    printf("### Perfect Rule Example ###\n");
    /*
      NOTE:
      - valid protocols: UDP or TCP
     */
    perfect_rule = &rule.rule_family.perfect_rule;

    if(1) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
      rule.rule_id = rule_id++, perfect_rule->queue_id = -1, perfect_rule->proto = 6,
	perfect_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]: did you enable the FlowDirector (insmod ixgbe.ko FdirMode=2)\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic 192.168.30.207:* -> *\n", rule.rule_id);
    }


    if(1) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
      rule.rule_id = rule_id++, perfect_rule->queue_id = -1, perfect_rule->proto = 17,
	perfect_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]: did you enable the FlowDirector (insmod ixgbe.ko FdirMode=2)\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping UDP traffic 192.168.30.207:* -> *\n", rule.rule_id);
    }
  }


  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);


  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  if(dna_mode)
    num_threads = 1;
  else {
    if(num_threads > 1) wait_for_packet = 1;
  }

  pfring_enable_ring(pd);

  if(0) {
    filtering_rule rule;

    memset(&rule, 0, sizeof(rule));

    rule.rule_id = 5;
    rule.rule_action = forward_packet_and_stop_rule_evaluation;
    rule.core_fields.port_low = 80, rule.core_fields.port_high = 80;

    if(pfring_add_filtering_rule(pd, &rule) < 0)
      printf("pfring_add_hash_filtering_rule(2) failed\n");
    else
      printf("Rule added successfully...\n");
  }

  if(1) {
    filtering_rule rule;

#define DUMMY_PLUGIN_ID   1

    memset(&rule, 0, sizeof(rule));

    rule.rule_id = 5;
    rule.rule_action = forward_packet_and_stop_rule_evaluation;
    rule.core_fields.proto = 6 /* tcp */;
    // rule.plugin_action.plugin_id = DUMMY_PLUGIN_ID; /* Dummy plugin */
    // rule.extended_fields.filter_plugin_id = DUMMY_PLUGIN_ID; /* Enable packet parsing/filtering */

    if(pfring_add_filtering_rule(pd, &rule) < 0)
      printf("pfring_add_hash_filtering_rule(2) failed\n");
    else
      printf("Rule added successfully...\n");
  }

  if(num_threads > 1) {
    pthread_t my_thread;
    long i;

    for(i=1; i<num_threads; i++)
      pthread_create(&my_thread, NULL, packet_consumer_thread, (void*)i);
  }

  packet_consumer_thread(0);

  pfring_close(pd);

  sleep(3);

  return(0);
}
