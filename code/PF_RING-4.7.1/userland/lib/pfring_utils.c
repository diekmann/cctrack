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


#include "pfring.h"
#include "pfring_utils.h"

int parse_pkt(u_char *pkt, struct pfring_pkthdr *hdr)
{
  struct iphdr *ip;
  struct eth_hdr *eh = (struct eth_hdr*)pkt;
  u_int16_t displ;

  memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));

  hdr->extended_hdr.parsed_header_len = 0;
  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;

  if(hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */)
    {
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + sizeof(struct eth_hdr);
      hdr->extended_hdr.parsed_pkt.vlan_id = (pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 14] & 15) * 256
	+ pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 15];
      hdr->extended_hdr.parsed_pkt.eth_type = (pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 16]) * 256
	+ pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 17];
      displ = 4;
    }
  else
    {
      displ = 0;
      hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */
    }

  if(hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IP */) {
    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset+displ+sizeof(struct eth_hdr);
    ip = (struct iphdr*)(pkt+hdr->extended_hdr.parsed_pkt.offset.l3_offset);

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr), hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr), hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;

    if((ip->protocol == IPPROTO_TCP) || (ip->protocol == IPPROTO_UDP)) {
      u_int16_t ip_len = ip->ihl*4;

      hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len;

      if(ip->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp = (struct tcphdr*)(pkt+hdr->extended_hdr.parsed_pkt.offset.l4_offset);
	hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
	hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset+(tcp->doff * 4);
	hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
	hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
	hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) + (tcp->rst * TH_RST_MULTIPLIER) +
	  (tcp->psh * TH_PUSH_MULTIPLIER) + (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);
      } else if(ip->protocol == IPPROTO_UDP) {
	struct udphdr *udp = (struct udphdr*)(pkt+hdr->extended_hdr.parsed_pkt.offset.l4_offset);
	hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
	hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset+sizeof(struct udphdr);
      } else
	hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    } else
      hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;

    return(1); /* IP */
  } /* TODO: handle IPv6 */

  return(0); /* No IP */
}

/* ******************************* */

int set_if_promisc(const char *device, int set_promisc) {
  int sock_fd, ret = 0;
  struct ifreq ifr;

  if(device == NULL) return(-3);

  sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_fd <= 0) return(-1);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if(ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
    close(sock_fd);
    return(-2);
  }

  ret = ifr.ifr_flags & IFF_PROMISC;
  if(set_promisc) {
    if(ret == 0) ifr.ifr_flags |= IFF_PROMISC;
  } else {
    /* Remove promisc */
    if(ret != 0) ifr.ifr_flags &= ~IFF_PROMISC;
  }

  if(ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1)
    return(-1);

  close(sock_fd);
  return(ret);
}

/* *************************************** */

char* format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals) {
  u_int a1 = ((u_long)val / 1000000000) % 1000;
  u_int a = ((u_long)val / 1000000) % 1000;
  u_int b = ((u_long)val / 1000) % 1000;
  u_int c = (u_long)val % 1000;
  u_int d = (u_int)((val - (u_long)val)*100) % 100;  

  if(add_decimals) {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else
      snprintf(buf, buf_len, "%.2f", val);
  } else {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else
      snprintf(buf, buf_len, "%u", (unsigned int)val);
  }

  return(buf);
}

/* *************************************** */

#ifndef HAVE_PTHREAD_SET_AFFINITY
int pthread_attr_setaffinity_np (pthread_attr_t *__attr,
				 size_t cpusetsize,
				 cpu_set_t *__cpuset) {
  return(0);
}

extern int pthread_setaffinity_np (pthread_t __th, size_t __cpusetsize,
				   cpu_set_t *__cpuset) {
  return(0);
}

#endif
