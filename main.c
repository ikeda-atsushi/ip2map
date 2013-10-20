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
#include <string.h>
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
#include <signal.h>
#include <sys/select.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <curl/curl.h>
#include <gtk/gtk.h>

#include "analyze.h"

#define Latt 0
#define Long 1

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

typedef struct SocketDesc {
  struct SocketDesc *next; 
  struct SocketDesc *preb;
  int desc;
} SocketDesc;

SocketDesc *__sdhead;
static GeoIP *__geo;

typedef struct IP2Location {
  struct IP2Location *next;
  struct IP2Location *preb;
  GeoIPRecord        *geoip;
  double latitude;
  double longitude;
  int marker;
  unsigned char saddr[4];
  int     port;
} IP2Location;

IP2Location *__ip2loc;

/* GEOIP data base */
static char * DB_CITY ="/usr/share/GeoIP/GeoIPCity.dat";
/* map image tmp file */
static char * TMP_PNG = "tmp.png";

/* number of IP address */
static char *IP_FOWARD = "/proc/sys/net/ipv4/ip_forward";

/* label of markers */
static char *ABC       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char        *MARKER    = "markers=size:tiny%7Ccolor:blue%7Clabel:S%7C<LATI>,<LONG>";
/* REST for Google static map  */
static char *STATICMAP_BASE_URL = "https://maps.google.com/maps/api/staticmap?center=38.822591,-98.818363&zoom=0&size=400x200&maptype=terrain&sensor=false";

/* program name = argv[0] */
char *__prog;

IP2Location   *getCityFromIP(struct iphdr *iphdr);
SocketDesc    *OpenRawSocket(int argc, char **dev, int promiscFlag, int ipOnly);
char          *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int            turnOffIPforward(void);

static void 
button_clicked(GtkWidget *button, gpointer user_data)
{
  GeoIP_delete(__geo);
  gtk_main_quit();
}

void
buildURL(char **url)
{
  int len, n;
  char *tmp, *c;
  IP2Location *ip;

  tmp = malloc(512);
  len = 0;

  for (ip=__ip2loc;ip!=__ip2loc;ip=ip->next) 
    {
      n = (int)((ip - __ip2loc)/26);
      sprintf(tmp, "&markers=size:tiny|  color:blue|  label:%c|  %9.6f,%9.6f", ABC[n], ip->latitude, ip->longitude);
      len = strlen(*url);
      strcat(*url, tmp);
    } 

  len = strlen(*url);
  for (c=*url;c-*url<=len;c++) {
    if (*c == '|') {
      c[0]='%';
      c[1]='7';
      c[2]='C';
    }
  }

#ifdef URL
  printf("URL: %s\n", *url);
#endif
}

int
turnOffIPforward(void)
{
  FILE *fp;

  fprintf(stderr,"Disable IP foward\n" );
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

IP2Location *
getCityFromIP(struct iphdr *iphdr)
{
  char *buf;
  u_char *tcphdr;
  GeoIPRecord *rec;
  IP2Location *newp;
  IP2Location *pt;
  static int BUF_SIZE = 128;

  rec = NULL;
  tcphdr = (u_char *)iphdr;
  buf = malloc(BUF_SIZE);

  if (is_privateIP(ip_ip2str(iphdr->saddr, buf, BUF_SIZE)))  {
    free(buf);
    return (NULL);
  }

  /* check if it's from the same source */
  for (pt=__ip2loc;pt!=__ip2loc;pt=pt->next) {
    if (pt->saddr == iphdr->saddr) {
      // if it's same,  return
      return(pt);
    }
  } // for

  if ((rec=GeoIP_record_by_addr(__geo, ip_ip2str(iphdr->saddr, buf, BUF_SIZE))) == NULL) {
    fprintf(stderr, "error on getting geocode\n");
    free(buf);
    return (NULL);
  }

  tcphdr += sizeof(struct iphdr);

  //#ifdef GEOCODE
  fprintf(stdout, "===\n");
  fprintf(stdout, "IP         : %s\n", ip_ip2str(iphdr->saddr, buf, BUF_SIZE));
  fprintf(stdout, "Port       : %u\n", ntohs(((struct tcphdr *)tcphdr)->dest));
  fprintf(stdout, "Contry     : %s\n", rec->country_name);
  fprintf(stdout, "City       : %s\n", rec->city);
  fprintf(stdout, "Postal code: %s\n", rec->postal_code);
  fprintf(stdout, "Latitude   : %10.6f\n", rec->latitude);
  fprintf(stdout, "Longitude  : %10.6f\n\n", rec->longitude);
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
  newp->latitude   = rec->latitude;
  newp->longitude  = rec->longitude;
  newp->next       = __ip2loc->next;
  newp->next->preb = newp;
  newp->preb       = __ip2loc;
  __ip2loc->next   = newp;

  free(buf);

  return (newp);
}

SocketDesc *
OpenRawSocket(int cnt, char **dev, int promiscFlag, int ipOnly)
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
	return(-1);
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

// SIGUSR1
void
sigusr1_handler(int sig)
{
  fprintf(stdout, "signal USR1 called\n");
}

// SIGUSR2
void
sigusr2_handler(int sig)
{
  fprintf(stdout, "signal USR2 called\n");
}

int
init(void)
{

  /* SIGUSR1のシグナルハンドラを設定 */
  signal(SIGUSR1, sigusr1_handler);

  /* SIGUSR2のシグナルハンドラを設定 */
  signal(SIGUSR2, sigusr2_handler);
  
  if ((__geo=GeoIP_open(DB_CITY, 0))==NULL) {
    fprintf(stderr, "%s: GeoIPCity.dat does not exist\n", __prog);
    return (-1);
  }

  if ((__ip2loc=(IP2Location *)malloc(sizeof(IP2Location)))==NULL) {
    fprintf(stderr, "%s: not enough memory\n", __prog);
    return(-1);
  }

  __ip2loc->next       = __ip2loc;
  __ip2loc->preb       = __ip2loc;
  __ip2loc->geoip      = NULL;
  __ip2loc->latitude   = 1000.0;
  __ip2loc->longitude  = 1000.0;
  __ip2loc->port       = -1;

  if ((__sdhead=(SocketDesc *)malloc(sizeof(SocketDesc)))==NULL) {
    fprintf(stderr, "%s: not enough memory\n", __prog);
    return(-1);
  }
  __sdhead->desc = -1;
  __sdhead->next = __sdhead;
  __sdhead->preb = __sdhead;

  curl_global_init(CURL_GLOBAL_ALL);

  return(0);
}

int
main(int argc, char **argv)
{
  int  i, n, ndfd, size, len;
  u_char *buf;
  char *URL, *rest, *tmp, *c;
  fd_set readfds;
  sigset_t sigset;
  CURL *curl;
  CURLcode res;
  SocketDesc *sptr, *sdp, *mainp;
  GtkWidget *window;
  IP2Location *ip;

  static int BUF_SIZE = 2048;

  __prog = argv[0];

  if (argc <= 1) {
    fprintf(stderr, "Usage: %s dev1 [dev2 ...]\n", __prog);
    return (-1);
  }

  init();

  gtk_init(&argc, &argv);

  if ((buf=(u_char *)malloc(BUF_SIZE))==NULL) {
    perror("malloc");
    return(-1);
  }

  if ((URL=(char *)malloc(BUF_SIZE))==NULL) {
    perror("Not enoght memory");
    GeoIP_delete(__geo);
    return (-1);
  }
  URL[0]='\0';

  if ((sdp=OpenRawSocket(argc-1, argv, 0, 0))<0) {
    fprintf(stderr, "InitRawSocket:error:%s'n", argv[1]);
    free(buf);
    GeoIP_delete(__geo);
    return (-1);
  }

  /* SIGUSR1のシグナルを設定 */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);

  i=0;
  while(i++<=10) {

      FD_ZERO(&readfds);
      sptr = __sdhead;
      ndfd = 0;

      do {
	FD_SET(sptr->desc, &readfds);
	ndfd = max(ndfd, sptr->desc);
	sptr = sptr->next;
      } while (sptr != __sdhead);

      /* SIGUSR2が来るまでselectはblockし続けます */
      /* SIGUSR1ではEINTRは返りません */
      n = pselect(ndfd+1, &readfds, NULL, NULL, NULL, &sigset);
      /*    if (n == -1 && errno == EINTR)
	    continue; */
      if (n < 0) {
	fprintf (stderr, "%s: select error\n", __prog);
	GeoIP_delete(__geo);
	return (-1);
      }
      mainp = __sdhead;
      do {
	if (FD_ISSET(mainp->desc, &readfds)) {
	  
	  if ((size=read(mainp->desc, buf, BUF_SIZE))<=0) {
	    if (size==0) break;
	    fprintf(stderr, "%s: error on read\n", __prog);
	    break;
	  } 

	  AnalyzePacket(buf, size);
	}
	mainp = mainp->next;
      } while (mainp != __sdhead);
  } // while

  // Build URL to get a map from Google
  if ((rest = malloc(4096))==NULL) {
    fprintf(stderr, "No memory");
    return -1;
  }
  rest[0]='\0';

  if ((tmp = malloc(512))==NULL) {
    fprintf(stderr, "No memory");
    return -1;
  }
  tmp[0]='\0';

  strcat(rest, STATICMAP_BASE_URL);

  ip=__ip2loc;
  do { 
    if (ip->port != -1) {
      char buf[512];
      fprintf(stdout, "IP         : %s\n", ip_ip2str(ip->saddr, buf, 512));
      fprintf(stdout, "Port       : %d\n", ip->port);
      fprintf(stdout, "Latitude   : %10.6f\n", ip->latitude);
      fprintf(stdout, "Longitude  : %10.6f\n", ip->longitude);
      fprintf(stdout, "Marker     : %d\n\n", ip->marker);
      if (ip->marker) {
	sprintf(tmp, "&markers=size:tiny|  color:blue|  label:%c:|  %f,%f", ABC[i], ip->latitude, ip->longitude);
	strcat(rest, tmp);
	tmp[0]='\0';
      }
      ip=ip->next;
    }
  } while(ip!=__ip2loc);
  
  len = strlen(rest);
  for (c=rest;c-rest<=len;c++) {
    if (*c == '|') {
      c[0]='%';
      c[1]='7';
      c[2]='C';
    }
  } // for

  fprintf(stdout, "REST: %s\n", rest);

  curl = curl_easy_init();
  if (curl) {
    FILE *fp;

    fp = fopen(TMP_PNG, "w");

    curl_easy_setopt(curl, CURLOPT_URL, rest);

    /* write image on a file */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    res = curl_easy_perform(curl);
    if (res!= CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)); 
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fclose(fp);
  }
  free(rest);
  free(tmp);

  sptr = __sdhead;
  do {
    close(sdp->desc);
    sptr = sptr->next;
  } while (sptr != __sdhead);
  free(buf);
  free(URL);


  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  gtk_widget_set_size_request(window, 500, 300);
  {
    GtkWidget *box;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

    gtk_container_add(GTK_CONTAINER(window), box);
    {
      GtkWidget *image;
      GtkWidget *button;
      
      // a widget for image
      image = gtk_image_new_from_file(TMP_PNG);
      gtk_box_pack_start(GTK_BOX(box), image, TRUE, TRUE, 1);
      
      // button
      button = gtk_button_new_with_label("Quit");
      gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 1);
      g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(button_clicked), NULL);
    }
  }
  g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
  gtk_widget_show_all(window);

  gtk_main();

  return 0;
}
