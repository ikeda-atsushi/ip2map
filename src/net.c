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
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <sys/select.h>
#include <errno.h>

#include "ip2loc.h"

/* number of IP address */
static char *IP_FOWARD = "/proc/sys/net/ipv4/ip_forward";

/* program name = argv[0] */
extern char         *__prog;
/* link to socket discpritor */
extern SocketDesc   *__sdhead;
/*  GEO descpritor */
extern GeoIP        *__geo;
/* link to hold GEO info */
extern IP2Location  *__ip2loc;

SocketDesc     *openRawSocket(int argc, char **dev, int promiscFlag, int ipOnly);
IP2Location    *getCityFromIP(struct iphdr *iphdr);
char           *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int             is_privateIP(const char *ip);
int             turnOffIPforward(void);
int             port_in_use(int port);

SocketDesc *
openRawSocket(int cnt, char **dev, int promiscFlag, int ipOnly)
{
  int i, on, soc;
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  SocketDesc *newp;

  while (cnt>0)
    {
      if(ipOnly) {
	if ((soc=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0) {
	  perror("socket");
	  return (NULL);
	}
      } else {
	if ((soc=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) {
	  perror("socket");
	  return (NULL);
	}    
      }

      /* Enable address reuse */
      on = 1;
      if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))<0) {
	perror("sockopt");
	close(soc);
	return (NULL);
      }

      memset(&ifreq, 0, sizeof(struct ifreq));
      strncpy(ifreq.ifr_name, dev[cnt], sizeof(ifreq.ifr_name)-1);
      if (ioctl(soc,SIOCGIFINDEX,&ifreq)<0) {
	perror("ioctl");
	close(soc);
	return (NULL);
      }
      cnt = cnt - 1;

      memset(&sa, 0, sizeof(sa));
      sa.sll_family=PF_PACKET;
      if (ipOnly) {
	sa.sll_protocol = htons(ETH_P_IP);
      } else {
	sa.sll_protocol = htons(ETH_P_ALL);
      }
      sa.sll_ifindex = ifreq.ifr_ifindex;
      if (bind(soc, (struct sockaddr *)&sa, sizeof(sa))<0){
	perror("bind");
	close(soc);
	return (NULL);
      }

      /* Alloc memory on SocketDesc */
      if ((newp=(SocketDesc *)malloc(sizeof(SocketDesc)))==NULL) {
	fprintf(stderr, "%s: not enough memory\n", __prog);
	return(NULL);
      }
      if (__sdhead==NULL) {
	fprintf(stderr, "%s: internal inconsistency\n", __prog);
	return (NULL);
      } 

      /* link in a new SocketDesc */
      newp->next       = __sdhead->next;
      newp->next->preb = newp;
      newp->preb       = __sdhead;
      __sdhead->next   = newp;
      newp->desc       = soc;
      
      if (promiscFlag) {
	if (ioctl(soc, SIOCGIFFLAGS, &ifreq)<0) {
	  perror("ioctl");
	  close(soc);
	  return (NULL);
	}
	ifreq.ifr_flags = ifreq.ifr_flags|IFF_PROMISC;
	if (ioctl(soc, SIOCSIFFLAGS,&ifreq)<0) {
	  perror("ioctl");
	  close(soc);
	  return (NULL);
	}
      }
      
      /* flush all received packets.
       *
       * raw-socket receives packets from all interfaces
       * when the socket is not bound to an interface
       */
      do {
	fd_set fds;
	struct timeval t;
	u_char buf[2048];
	
	FD_ZERO(&fds);	
	FD_SET(soc, &fds);
	memset(&t, 0, sizeof(t));
	i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
	if (i > 0) {
	  recv(soc, buf, i, 0);
	}
      } while (i);
    } // while(cnt>0)

  return (newp);
}

IP2Location *
getCityFromIP(struct iphdr *iphdr)
{
  char *buf;
  u_char *tcphdr;
  GeoIPRecord *rec;
  IP2Location *newp;
  IP2Location *pt;
  static int BUF_SIZE = 16;

  rec = NULL;
  tcphdr = (u_char *)iphdr;
  buf = malloc(BUF_SIZE);

  if (is_privateIP(ip_ip2str(iphdr->saddr, buf, BUF_SIZE)))  {
    free(buf);
    return (NULL);
  }

  /* check if packet is from the same source */
  pt=__ip2loc;
  do {
    if ((u_int32_t)(pt->saddr) == iphdr->saddr) {
      // if it's same,  return
      return(pt);
    }
    pt=pt->next;
  } while (pt!=__ip2loc);

  if ((rec=GeoIP_record_by_addr(__geo, ip_ip2str(iphdr->saddr, buf, BUF_SIZE))) == NULL) {
    fprintf(stderr, "error on getting geocode\n");
    free(buf);
    return (NULL);
  }

  tcphdr += sizeof(struct iphdr);

  //#ifdef GEOCODE
  fprintf(stdout, "=== link-in ==\n");
  fprintf(stdout, "IP         : %s\n", ip_ip2str(iphdr->saddr, buf, BUF_SIZE));
  fprintf(stdout, "Port       : %u\n", ntohs(((struct tcphdr *)tcphdr)->dest));
  fprintf(stdout, "Contry     : %s\n", rec->country_name);
  fprintf(stdout, "City       : %s\n", rec->city);
  fprintf(stdout, "Postal code: %s\n", rec->postal_code);
  fprintf(stdout, "Latitude   : %10.6f\n", rec->latitude);
  fprintf(stdout, "Longitude  : %10.6f\n\n", rec->longitude);
  fprintf(stdout, "=======\n\n");
  //#endif

  if (__ip2loc->port == -1) {
    //  head of link 
    newp = __ip2loc;
  } else {
    if ((newp=(IP2Location *)malloc(sizeof(IP2Location)))==NULL) {
      fprintf(stderr, "%s: not enough memory\n", __prog);
      return(NULL);
    }
  }
  newp->marker = 1;

  pt = __ip2loc;
  do  {
    if (pt->latitude == rec->latitude 
	&& pt->longitude == rec->longitude) {
      newp->marker = 0;
      break;
    }
    pt = pt->next;
  } while(pt!=__ip2loc);

  newp->geoip      = rec;
  newp->port       = ntohs(((struct tcphdr *)tcphdr)->dest);
  newp->saddr      = iphdr->saddr;
  newp->latitude   = rec->latitude;
  newp->longitude  = rec->longitude;
  /* link in */
  newp->next       = __ip2loc->next;
  newp->next->preb = newp;
  newp->preb       = __ip2loc;
  // newp->preb->next = newp;
  __ip2loc->next   = newp;

  if (newp->next==0) {
    abort();
  }

  free(buf);

  return (newp);
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
turnOffIPforward(void)
{
  FILE *fp;

  if((fp=fopen(IP_FOWARD, "w"))==NULL) {
    perror("fopen");
    return(-1);
  }

  fputs("0", fp);
  fclose(fp);
  return (0);
}

int
is_privateIP(const char *ip)
{
  int dec;
  int private;

  private  = 0;
  if (ip[0]=='1'&&ip[1]=='0'&&ip[2]=='.') {
    private = 1;
  } else if (ip[0]=='1'&&ip[1]=='7'&&ip[2]=='2') {
    dec = ip[4]-0x30*10+ip[5]-0x30;
    if (dec>=16 && dec<=31) {
      private = 1;
    }
  } else if ((ip[0]=='1' && ip[1]=='9' && ip[2]=='2') && (ip[4]=='1' && ip[5]=='6' && ip[6]=='8')) {
    private = 1;
  }
  
  return (private);
}

int
port_in_use(int port)
{
  int sfd;
  struct sockaddr_in *serv_addr;

  if ((serv_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)))==NULL) {
      fprintf(stderr, "%s: not enough memory\n", __prog);
      return(-1);
  }

  if ((sfd = socket(AF_INET, SOCK_STREAM, 0))<0) {
    fprintf(stderr, "%s: Socket open error\n", __prog);
    return(-1);
  }
  
  bzero((char *)serv_addr, sizeof(struct sockaddr_in));
  serv_addr->sin_family = AF_INET;
  serv_addr->sin_addr.s_addr = INADDR_ANY;
  serv_addr->sin_port = htons(port);

  if (bind(sfd, (struct sockaddr *)serv_addr, sizeof(struct sockaddr_in))<0) {
    if (errno == EADDRINUSE) {
      /* address in use */
      close(sfd);
      return (1);
    }
    fprintf(stderr, "%s: bind  error\n", __prog);
    close(sfd);
    return(-1);
  }
  close(sfd);

  return (0);
}

