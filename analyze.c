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

#include "checksum.h"
#include "print.h"
#include "analyze.h"

#ifdef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

double    ** getCityFromIP(struct iphdr *iphdr);

int
AnalyzeArp(u_char *data, int size)
{
  u_char *ptr;
  int    lest;
  struct ether_arp *arp;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct ether_arp))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct iphdr)\n", lest);
      return (-1);
    }

  arp = (struct ether_arp *)ptr;
  ptr += sizeof(struct ether_arp);
  lest -= sizeof(struct ether_arp);

#ifdef PRINT
  PrintArp(arp, stderr);
#endif

  return (0);
}

int
AnalyzeIcmp(u_char *data, int size)
{
  u_char *ptr;
  int lest;

  struct icmp *icmp;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct icmp))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct icmp)\n", lest);
      return (-1);
    }
  
  icmp = (struct icmp *)ptr;
  ptr += sizeof(struct icmp);
  lest -= sizeof(struct icmp);

#ifdef PRINT
  PrintIcmp(icmp, stderr);
#endif

  return (0);
}

int
AnalyzeIcmp6(u_char *data, int size)
{
  u_char *ptr;
  int lest;

  struct icmp6_hdr *icmp6;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct icmp6_hdr))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct icmp6_hdr)\n", lest);
      return (-1);
    }
  
  icmp6 = (struct icmp6_hdr *)ptr;
  ptr += sizeof(struct icmp6_hdr);
  lest -= sizeof(struct icmp6_hdr);

#ifdef PRINT
  PrintIcmp6(icmp6, stderr);
#endif

  return (0);
}

int
AnalyzeTcp(u_char *data, int size)
{
  u_char *ptr;
  int lest;

  struct tcphdr *tcphdr;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct tcphdr))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct tcphdr)\n", lest);
      return (-1);
    }
  
  tcphdr = (struct tcphdr *)ptr;
  ptr += sizeof(struct tcphdr);
  lest -= sizeof(struct tcphdr);

#ifdef PRINT
  PrintTcp(tcphdr, stderr);
#endif

  return (0);
}

int
AnalyzeUdp(u_char *data, int size)
{
  u_char *ptr;
  int lest;

  struct udphdr *udp;

  ptr = data;
  lest = size;

  if (lest<sizeof(struct udphdr))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct udphdr)\n", lest);
      return (-1);
    }
  
  udp = (struct udphdr *)ptr;
  ptr += sizeof(struct udphdr);
  lest -= sizeof(struct udphdr);

#ifdef PRINT
  PrintUdp(udp, stderr);
#endif 

  return (0);
}

int
AnalyzeIp(u_char *data, int size)
{
  int optionLen, len, lest;
  unsigned short sum;
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

  /*
   * get location from source IP address 
   */
  /*
    fprintf(fp, "\nGeoIP from source ********\n");
    fprintf(fp, "saddr=%s\n", ip_ip2str(iphdr->saddr, buf, 80));
  */

  if (getCityFromIP(iphdr)==NULL) {
    free(buf);
    return (-1);
  }

  /*
    fprintf(stdout, "\nGeoIP from destination ********\n");
    fprintf(stdout, "daddr=%s\n", ip_ip2str(iphdr->daddr, buf, 80));
  */

#ifdef DEST
  if (getCityFromIP(iphdr)==NULL) {
    free(buf);
    return (-1);
  }
  fprintf(stdout, "********\n");
#endif

#ifdef PRINT
  PrintIpHeader(iphdr, option, optionLen, stderr);
#endif

  if (iphdr->protocol == IPPROTO_ICMP)
    {
      len = ntohs(iphdr->tot_len)-iphdr->ihl*4;
      sum = checksum(ptr, len);
      if (sum != 0&&sum!=0xFFFF)
	{
	  fprintf(stderr, "bad icmp checksum\n");
	  free(buf);
	  return (-1);
	}
      AnalyzeIcmp(ptr, lest);
    } else if (iphdr->protocol == IPPROTO_TCP) 
    {
      len = ntohs(iphdr->tot_len)-iphdr->ihl*4;
      if (checkIPDATAchecksum(iphdr, ptr, len)==0)
	{
	  fprintf(stderr, "bad tcp checksum\n");
	  free(buf);
	  return (-1);
	}
      AnalyzeTcp(ptr, lest);
    } else if (iphdr->protocol == IPPROTO_UDP) 
      {
	struct udphdr *udphdr;
	udphdr=(struct udphdr *)ptr;
	len = ntohs(iphdr->tot_len)-iphdr->ihl*4;
	if (udphdr->check != 0 && checkIPDATAchecksum(iphdr, ptr, len) == 0)
	  {
	    fprintf(stderr, "bad udp checksum=\n");
	    free(buf);
	    return (-1);
	  }  
	AnalyzeUdp(ptr, lest);
      }

  free(buf);
  return (0);
}

int
AnalyzeIpv6(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  int len;

  struct ip6_hdr *ip6;

  len = 0;
  ptr = data;
  lest = size;

  if (lest<sizeof(struct ip6_hdr))
    {
      fprintf(stderr, "lest(%d)<sizeof(struct ip6_hdr)\n", lest);
      return (-1);
    }
  
  ip6 = (struct ip6_hdr *)ptr;
  ptr += sizeof(struct ip6_hdr);
  lest -= sizeof(struct ip6_hdr);

#ifdef PRINT
  PrintIp6Header(ip6, stderr);
#endif

  if (ip6->ip6_nxt==IPPROTO_ICMPV6)
    {
      len = ntohs(ip6->ip6_plen);
      if (checkIP6DATAchecksum(ip6, ptr, len)==0)
	{
	  fprintf(stderr, "bad icmp6 checksum\n");
	  return (-1);
	}
      AnalyzeIcmp6(ptr, lest);
    } else if (ip6->ip6_nxt==IPPROTO_TCP) 
    {
      if (checkIP6DATAchecksum(ip6, ptr, len)==0)
	{
	  fprintf(stderr, "bad tcp checksum\n");
	  return (-1);
	}
      AnalyzeTcp(ptr, lest);
    } else if (ip6->ip6_nxt == IPPROTO_UDP)
    {
      if (checkIP6DATAchecksum(ip6, ptr, len)==0)
	{
	  fprintf(stderr, "bad udp checksum\n");
	  return (-1);
	}
      AnalyzeUdp(ptr, lest);
    }
      
  return (0);
}

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
#ifdef PRINT      
      PrintEtherHeader(eh, stderr);
#endif
      AnalyzeArp(ptr, lest);
    } else if (ntohs(eh->ether_type)==ETHERTYPE_IP)
    {
#ifdef PRINT
      PrintEtherHeader(eh, stderr);
#endif
      AnalyzeIp(ptr, lest);
    } else if (ntohs(eh->ether_type)==ETHERTYPE_IPV6)
    {
#ifdef PRINT     
      PrintEtherHeader(eh, stderr);
#endif
      AnalyzeIpv6(ptr, lest);
    }
  return (0);
}
