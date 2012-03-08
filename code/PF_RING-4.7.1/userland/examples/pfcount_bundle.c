/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
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
#define DEFAULT_DEVICE     "eth0"

pfring *ring[MAX_NUM_BUNDLE_ELEMENTS];
pfring_bundle bundle;
int verbose = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 1, dna_mode = 0, do_shutdown = 0, num_ring;

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
  int i;
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts[MAX_NUM_BUNDLE_ELEMENTS] = { 0 };
  u_int64_t diff, tot_pkts, tot_drops;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  tot_pkts = tot_drops = 0;
  for(i=0; i<bundle.num_sockets; i++)  {
    if(pfring_stats(ring[i], &pfringStat) >= 0) {
      if(print_all && (lastTime.tv_sec > 0)) {
	deltaMillisec = delta_time(&endTime, &lastTime);
	diff = pfringStat.recv-lastPkts[i];
	tot_pkts += diff, tot_drops += pfringStat.drop;
	fprintf(stderr, "[%d] Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec][%llu drops]\n",
		i, (long long unsigned int)diff,
		deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)),
		(long long unsigned int)pfringStat.drop);
      }
      
      lastPkts[i] = pfringStat.recv;
    }
  }
  
  fprintf(stderr, "\nAggregate Stats:  %llu pkts [%.1f ms][%.1f pkt/sec][%llu drops]\n",
	  (long long unsigned int)tot_pkts,
	  deltaMillisec, ((double)tot_pkts/(double)(deltaMillisec/1000)),
	  (long long unsigned int)tot_drops);

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  pfring_bundle_close(&bundle);

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

  numPkts++, numBytes += h->len;
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
  printf("pfcount\n(C) 2005-11 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device@channel for channels\n");

  /* printf("-f <filter>     [pfring filter]\n"); */

  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-s <string>     String to search on packets\n");
  printf("-l <len>        Capture length\n");
  printf("-w <watermark>  Watermark\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-r              Rehash RSS packets\n");
  printf("-a              Active packet wait\n");
  printf("-v              Verbose\n");
}

/* *************************************** */

void* packet_consumer(void) {
  u_char* buffer;

  while(1) {
    struct pfring_pkthdr hdr;

    if(do_shutdown) break;
    
    if(pfring_bundle_read(&bundle, &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      dummyProcesssPacket(&hdr, buffer, 0);
    } else {
      /* usleep(100); */
    }
  }
  
  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *string = NULL, *dev;
  int promisc, snaplen = DEFAULT_SNAPLEN;
  packet_direction direction = rx_and_tx_direction;
  u_int16_t watermark = 0, rehash_rss = 0;
  u_int32_t version;
  u_int16_t cpu_percentage = 0;

  startTime.tv_sec = 0;
  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"hi:dl:vs:ae:w:b:r" /* "f:" */)) != '?') {
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
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
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
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'r':
      rehash_rss = 1;
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  printf("Capturing from bundle %s\n", device);
  
  dev = strtok(device, ";");
  num_ring = 0;
  init_pfring_bundle(&bundle, pick_round_robin);

  while(dev != NULL) {
    printf("Adding %s to bundle\n", dev);

    ring[num_ring] = pfring_open(dev, promisc, snaplen, 0);

    if(ring[num_ring] == NULL) {
      printf("pfring_open error (perhaps you use quick mode and have already a socket bound to %s ?)\n", dev);
      return(-1);
    } 
    
    pfring_set_application_name(ring[num_ring], "pfcount_bundle");
    pfring_version(ring[num_ring], &version);

    if(watermark > 0) {
      int rc;

      if((rc = pfring_set_poll_watermark(ring[num_ring], watermark)) != 0)
	printf("pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
    }
    
    add_to_pfring_bundle(&bundle, ring[num_ring]);

    num_ring++;    
    dev = strtok(NULL, ";");
  }

  
  printf("Using PF_RING v.%d.%d.%d\n",
	 (version & 0xFFFF0000) >> 16,
	 (version & 0x0000FF00) >> 8,
	 version & 0x000000FF);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  packet_consumer();

  pfring_bundle_close(&bundle);

  return(0);
}
