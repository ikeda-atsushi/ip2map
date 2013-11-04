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
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "checksum.h"
#include "ip2loc.h"

#ifdef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

int AnalyzeIp(u_char *data, int size);
int AnalyzeIpv6(u_char *data, int size);
int AnalyzePacket(u_char *data, int size);
IP2Location   *getCityFromIP(struct iphdr *iphdr);

int
AnalyzePacket(u_char *data, int size)
{
  u_char *ptr;
  int lest;

  struct ether_header *eh;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct ether_header))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n", lest);
      return (-1);
    }
  
  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);

  if (ntohs(eh->ether_type)==ETHERTYPE_ARP)
    {
      /* Arp */
    } else if (ntohs(eh->ether_type)==ETHERTYPE_IP)
    {
      /* IPV4 */
      AnalyzeIp(ptr, lest);
    } else if (ntohs(eh->ether_type)==ETHERTYPE_IPV6)
    {
      /* IPV6 */
      AnalyzeIpv6(ptr, lest);
    }

  return (0);
}

int
AnalyzeIp(u_char *data, int size)
{
  int optionLen, lest;
  u_char *option, *ptr;
  struct iphdr *iphdr;

  void *buf = malloc(80);

  ptr = data;
  lest = size;

  if (lest<sizeof(struct iphdr))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct iphdr)\n", lest);
      free(buf);
      return (-1);
    }
  
  iphdr = (struct iphdr *)ptr;
  ptr += sizeof(struct iphdr);
  lest -= sizeof(struct iphdr);

  optionLen = iphdr->ihl*4-sizeof(struct iphdr);

  if (optionLen > 0)
    {
      if (optionLen >= 1500)
	{
	  fprintf(stderr, "optionLen(%d)<sizeof(struct iphdr)\n", lest);
	  free(buf);
	  return (-1);
	}
      option =  ptr;
      ptr += optionLen;
      lest -= optionLen;
    }

  if (checkIPchecksum(iphdr, option, optionLen)==0)
    {
      fprintf(stderr,"bad ip checksum\n");
      free(buf);
      return (-1);
    }

  /* find a city */
  if (getCityFromIP(iphdr)==NULL) {
    free(buf);
    return (-1);
  }

#ifdef DEST
  if (getCityFromIP(iphdr)==NULL) {
    free(buf);
    return (-1);
  }
  fprintf(stdout, "********\n");
#endif

  free(buf);
  return (0);
}

int
AnalyzeIpv6(u_char *data, int size)
{
  int lest;
  u_char *ptr;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct ip6_hdr)) {
      fprintf(stderr, "lest(%d)<sizeof(struct ip6_hdr)\n", lest);
      return (-1);
    }
  
  ptr += sizeof(struct ip6_hdr);
  lest -= sizeof(struct ip6_hdr);

  return (0);
}

