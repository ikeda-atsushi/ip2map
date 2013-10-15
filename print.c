/***********************************************************************************************************************
 *
 * ip2map :  This program shows you the locations of the computers that are sending packets to your computer on a map.  
 * Copyright (C) 2013 Atsushi Ikeda: ikeda.atsushi@gmail.com							        
 * 														        
 * This program is free software; you can redistribute it and/or						        
 * modify it under the terms of the GNU General Public License							        
 * as published by the Free Software Foundation; either version 2						        
 * of the License, or (at your option) any later version.							        
 * 														        
 * This program is distributed in the hope that it will be useful,						        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of						        
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						        
 * GNU General Public License for more details.									        
 *														        
 * You should have received a copy of the GNU General Public License						        
 * along with this program; if not, write to the Free Software							        
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.				        
 *
 ************************************************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "print.h"

#ifdef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

static char *Proto[] = {
  "undefined,",
  "ICMP,",
  "IGMP,",
  "undefined,",
  "IPIP,",
  "undefined,",
  "TCP,",
  "undefined,",
  "EGP,",
  "undefined,",
  "undefined,",
  "undefined,",
  "PUP,",
  "undefined,",
  "undefined,",
  "undefined,",
  "undefined,",
  "UDP"
};

extern double **getCityFromIP(const char *ip);
extern double **geocode;

char *
my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size) 
{
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x\n",
	   hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

  return (buf);
}

char *
arp_ip2str(u_int8_t *ip, char *buf, socklen_t size)
{
  snprintf(buf, size, "%u.%u.%u.%u", ip[0],ip[1],ip[2],ip[3] );
  return (buf);
}

char *
ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
  struct in_addr *addr;

  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return (buf);
}

int 
PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
  char *buf;
  int BUF = 80;
  static int count=1;
  
  if ((buf=(char *)malloc(BUF))==NULL) {
    perror("malloc");
    return (-1);
  }

  fprintf(fp, "Ether Header(%u)----------------------------------\n", count++);
  fprintf(fp, "ether_dhost=%s", my_ether_ntoa_r(eh->ether_dhost, buf, BUF));
  fprintf(fp, "ether_shost=%s", my_ether_ntoa_r(eh->ether_shost, buf, BUF));
  fprintf(fp, "ether_type=0x%04x", ntohs(eh->ether_type));
  switch(ntohs(eh->ether_type))
    {
    case ETH_P_IP:
      fprintf(fp, "(IP)\n");
      break;
    case ETH_P_IPV6:
      fprintf(fp, "(IPV6)\n");
      break;
    case ETH_P_ARP:
      fprintf(fp, "(ARP)\n");
      break;
    default:
      fprintf(fp, "(unknown)\n\n");
      break;
    }
  free(buf);

  return (0);
}

int
PrintArp(struct ether_arp *arp, FILE *fp)
{
  char *buf;
  int BUF = 80;

  static char *hrd[] = {
    "From KA9Q: NET/ROM pseudo.",
    "Ethernet 10/100Mbps.",
    "Experimenal Ethernet.",
    "AX.25 Level 2.",
    "PROnet token ring.",
    "Chaosnet.",
    "IEEE 802.2 Ethernet/TR/TB.",
    "ARCnet.",
    "APPLEtalk.",
    "undefined.",
    "undefined.",
    "undefined.",
    "undefined.",
    "undefined.",
    "undefined.",
    "Frame Relay DLCI.",
    "undefined.",
    "undefined.",
    "undefined.",
    "ATM.",
    "undefined.",
    "undefined.",
    "undefined.",
    "Metricom STRIP (new IANA id)"
  };

  static char *op[] = {
    "undefined.",
    "ARP request.",
    "ARP reply.",
    "RARP request.",
    "RARP reply.",
    "undefined.",
    "undefined.",
    "undefined.",
    "InARP request.",
    "InARP reply.",
    "(ATM)ARP NAK."
  };

  if ((buf=(char *)malloc(BUF))==NULL) {
    perror("malloc");
    return (-1);
  }

  fprintf(fp, "arp_hrd=%u", ntohs(arp->arp_hrd));
  if (ntohs(arp->arp_hrd)<=23)
    {
      fprintf(fp, "(%s),",hrd[ntohs(arp->arp_hrd)]);
    } else {
      fprintf(fp, "(undefined),");
    }
  switch(ntohs(arp->arp_hrd))
    {
    case ETHERTYPE_IP:
      fprintf(fp, "(IP)\n");
      break;
    case ETHERTYPE_ARP:
      fprintf(fp, "(Address resolution)\n");
      break;
    case ETHERTYPE_REVARP:
      fprintf(fp, "(Reverse ARP)\n");
      break;
    case ETHERTYPE_IPV6:
      fprintf(fp, "(IPV6)\n");
      break;
    default:
      fprintf(fp, "(unknown)\n");
      break;
    }

  fprintf(fp, "arp_hln=%u," ,arp->arp_hln);
  fprintf(fp, "arp_pln=%u," ,arp->arp_pln);
  fprintf(fp, "arp_op=%u" ,arp->arp_op);
  if (ntohs(arp->arp_op)<=10)
    {
      fprintf(fp, "(%s)\n", op[ntohs(arp->arp_op)]);
    } else {
      fprintf(fp, "(undefined)\n");
    } 
  fprintf(fp, "arp_sha=%s" ,my_ether_ntoa_r(arp->arp_sha, buf, BUF));
  fprintf(fp, "arp_spa=%s\n" ,arp_ip2str(arp->arp_spa, buf, BUF));
  fprintf(fp, "arp_tha=%s" ,my_ether_ntoa_r(arp->arp_tha, buf, BUF));
  fprintf(fp, "arp_tpa=%s" ,my_ether_ntoa_r(arp->arp_tpa, buf, BUF));

  free(buf);
  return (0);
}


int
PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp)
{
  int i;
  char *buf;
  int BUF = 80;
  
  if ((buf=(char *)malloc(BUF))==NULL) {
    perror("malloc");
    return (-1);
  }

  fprintf(fp, "IP----------------------------------\n");
  fprintf(fp, "version=%u,",iphdr->version);
  fprintf(fp, "ihl=%u,",iphdr->ihl);
  fprintf(fp, "top=%u,",iphdr->tos);
  fprintf(fp, "tot_len=%u,",ntohs(iphdr->tot_len));
  fprintf(fp, "id=%u\n",ntohs(iphdr->id));
  fprintf(fp, "frag_off=0x%x,%u\n", (ntohs(iphdr->frag_off)>>13)&0x07, ntohs(iphdr->frag_off)&0x1FFF);
  fprintf(fp, "ttl=%u,",iphdr->ttl);
  fprintf(fp, "protocol=%u,",iphdr->protocol);
  if (iphdr->protocol<=17)
    {
      fprintf(fp,"(%s),", Proto[iphdr->protocol]);
    } else {
      fprintf(fp, "(undefined),");
    }
  fprintf(fp, "check=0x%x\n", iphdr->check);


  if (optionLen>0)
    {
      fprintf(fp, "option:");
      for(i=0;i<optionLen;i++) {
	if (i!=0)
	  {
	    fprintf(fp, ":0x%02x", option[i]);
	  } else {
	    fprintf(fp, "0x%02x", option[i]);
	  }
      } // for
    } // if

  free(buf);

  return (0);
}

int 
PrintIp6Header(struct ip6_hdr *ip6, FILE *fp)
{
  char *buf;
  int BUF = 80;
  
  if ((buf=(char *)malloc(BUF))==NULL) {
    perror("malloc");
    return (-1);
  }
  
  fprintf(fp, "ip6---------------------------------------------\n");

  fprintf(fp, "ip6_flow=0x%x,", ip6->ip6_flow);
  fprintf(fp, "ip6_plen=%d,", ip6->ip6_plen);
  fprintf(fp, "ip6_nxt=%u,", ip6->ip6_nxt);
  if (ip6->ip6_nxt<=17)
    {
      fprintf(fp, "(%s),",Proto[ip6->ip6_nxt]);
    } else {
      fprintf(fp, "(undefine),");
    }
  fprintf(fp, "ip6_hlim=%d,", ip6->ip6_hlim);
  fprintf(fp, "ip6_src=%s\n", inet_ntop(PF_INET6, &ip6->ip6_src, buf, BUF));
  fprintf(fp, "ip6_dst=%s\n", inet_ntop(PF_INET6, &ip6->ip6_dst, buf, BUF));

  free(buf);

  return (0);
}

int
PrintIcmp(struct icmp *icmp, FILE *fp)
{
  static char *icmp_type[] = {
    "Echo Replay",
    "undefined",
    "undefined",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "undefined",
    "undefined",
    "Echo Request",
    "Router Adverisement",
    "Router Selection",
    "Time Exceeded for Datagram",
    "Parameter Problem on Datagram",
    "Timestamp Request",
    "Timestamp Reply",
    "Information Request",
    "Information Replay",
    "Address Mask Request",
    "Address Mask Reply"
  };

  fprintf(fp, "ICMP--------------------------------------------\n");
  fprintf(fp,"icmp_type=%u", icmp->icmp_type);
  if (icmp->icmp_type<=18)
    {
      fprintf(fp, "(%s),", icmp_type[icmp->icmp_type]);
    } else {
      fprintf(fp, "(undefined),");
    }
    fprintf(fp,"icmp_code=%u,", icmp->icmp_code);
    fprintf(fp,"icmp_cksum=%u\n", ntohs(icmp->icmp_cksum));

    if (icmp->icmp_type==0||icmp->icmp_type==8)
      {
	fprintf(fp, "icmp_id=%u,", ntohs(icmp->icmp_id));
	fprintf(fp, "icmp_seq=%u\n", ntohs(icmp->icmp_seq));
      }

    return (0);
}

int
PrintIcmp6(struct icmp6_hdr *icmp6, FILE *fp)
{

  fprintf(fp, "ICMP6---------------------------------\n");
  fprintf(fp, "icmp6_type=%u", icmp6->icmp6_type);
  if (icmp6->icmp6_type == 1)
    {
      fprintf(fp, "(Destination Unreachable),");
    } else if (icmp6->icmp6_type == 2) {
      fprintf(fp, "(Packet too Big),");
    } else if (icmp6->icmp6_type == 3) {
      fprintf(fp,"(Time Exceeded),");
    } else if (icmp6->icmp6_type == 4) {
      fprintf(fp,"(Parameter Problem),");
    } else if (icmp6->icmp6_type == 128) {
      fprintf(fp,"(Echo Request),");
    } else if (icmp6->icmp6_type == 129) {
      fprintf(fp,"(Echo Reply),");
    } else {
      fprintf(fp,"(undefined),");
    }
  fprintf(fp, "icmp6_code=%u,",icmp6->icmp6_code);
  fprintf(fp, "icmp6_cksum=%u\n",icmp6->icmp6_cksum);
  if (icmp6->icmp6_type ==  128 || icmp6->icmp6_type == 129)
    {
      fprintf(fp, "icmp6_id=%u,",ntohs(icmp6->icmp6_id));
      fprintf(fp, "icmp6_seq=%u\n",ntohs(icmp6->icmp6_seq));
    }
  return (0);
}

int
PrintTcp(struct tcphdr *tcphdr, FILE *fp)
{
  fprintf(fp, "TCP----------------------------------------\n");
  fprintf(fp, "source port=%u,",ntohs(tcphdr->source));
  fprintf(fp, "dest port=%u\n",ntohs(tcphdr->dest));
  fprintf(fp, "sequence=%u\n", ntohs(tcphdr->seq));
  fprintf(fp, "ack_seq=%u\n",ntohs(tcphdr->ack_seq));
  fprintf(fp, "doff=%u,",tcphdr->doff);
  fprintf (fp, " flag: ");
  tcphdr->urg?fprintf(fp, " URG"):0;
  tcphdr->ack?fprintf(fp, " ACK"):0;
  tcphdr->psh?fprintf(fp, " PSH"):0;
  tcphdr->rst?fprintf(fp, " RST"):0;
  tcphdr->syn?fprintf(fp, " SYN"):0;
  tcphdr->fin?fprintf(fp, " FIN"):0;
  fprintf(fp, ", ");
  fprintf(fp, "window=%u\n",ntohs(tcphdr->window));
  fprintf(fp, "check=0x%x,",ntohs(tcphdr->check));
  fprintf(fp, "urp_ptr=%u\n",ntohs(tcphdr->urg_ptr));

  return (0);
}

int
PrintUdp(struct udphdr *udphdr, FILE *fp)
{
  fprintf(fp, "UDP-----------------------------------------\n");
  fprintf(fp, "source port=%u,", ntohs(udphdr->source));
  fprintf(fp, "dest port=%u\n", ntohs(udphdr->dest));
  fprintf(fp, "len=%u,", ntohs(udphdr->len));
  fprintf(fp, "check=0x%x\n", ntohs(udphdr->check));
  return (0);
}
