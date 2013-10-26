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
#include <cairo.h>
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
  u_int32_t saddr;
  int     port;
} IP2Location;

IP2Location *__ip2loc;

/* GEOIP data base */
static char * DB_CITY ="/usr/share/GeoIP/GeoIPCity.dat";
/* map image tmp file */
static char * TMP_PNG = "tmp.png";

/* number of IP address */
static char *IP_FOWARD = "/proc/sys/net/ipv4/ip_forward";

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
    if ((u_int32_t)(pt->saddr) == iphdr->saddr) {
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

  return(0);
}

static void 
do_drawing(cairo_t *cr, cairo_surface_t *image)
{
  cairo_set_source_surface(cr, image, 0, 0);
  cairo_paint(cr);    
}

static gboolean 
on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{      
  do_drawing(cr, (cairo_surface_t *)user_data);
  return FALSE;
}

int
main(int argc, char **argv)
{
  int  i, n, ndfd, size;
  u_char *buf;
  fd_set readfds;
  sigset_t sigset;
  SocketDesc *sptr, *sdp, *mainp;
  GtkWidget *window;
  IP2Location *ip;
  GtkWidget *image;

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


  if ((sdp=OpenRawSocket(argc-1, argv, 0, 0))<0) {
    fprintf(stderr, "InitRawSocket:error:%s'n", argv[1]);
    free(buf);
    GeoIP_delete(__geo);
    return (-1);
  }

  /* register SIGUSR1 */
   sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);

  i=0;
  while(i++<=20) {

      FD_ZERO(&readfds);
      sptr = __sdhead;
      ndfd = 0;

      do {
	FD_SET(sptr->desc, &readfds);
	ndfd = max(ndfd, sptr->desc);
	sptr = sptr->next;
      } while (sptr != __sdhead);

      /* Block till SIGUSR2 up */
      /* never return EINTER on SIGUSR1  */
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

  /* Run __ip2loc to make markers on map */
  ip=__ip2loc;
  do { 
    if (ip->port != -1) {
      char buf[512];
      fprintf(stdout, "IP         : %s\n", (char *)ip_ip2str((u_int32_t)ip->saddr, buf, 512));
      fprintf(stdout, "Port       : %d\n", ip->port);
      fprintf(stdout, "Latitude   : %10.6f\n", ip->latitude);
      fprintf(stdout, "Longitude  : %10.6f\n", ip->longitude);
      fprintf(stdout, "Marker     : %d\n\n", ip->marker);
      ip=ip->next;
    }
  } while(ip!=__ip2loc);
  
  /* close socket */
  sptr = __sdhead;
  do {
    close(sdp->desc);
    sptr = sptr->next;
  } while (sptr != __sdhead);
  free(buf);


  /* graphics */
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  {
    GtkWidget *box;
    GtkWidget *canvas;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_add(GTK_CONTAINER(window), box);

    canvas = gtk_drawing_area_new();

    {
      GtkWidget *button;
      
      image = (GtkWidget *)cairo_image_surface_create_from_png(TMP_PNG);

      /* widget for image */
      gtk_box_pack_start(GTK_BOX(box), canvas, TRUE, TRUE, 1);

      gtk_window_set_title(GTK_WINDOW(window), "IP locator");

      gtk_widget_set_size_request(window, cairo_image_surface_get_width((cairo_surface_t *)image) * 1.1,
				  cairo_image_surface_get_height((cairo_surface_t *)image) * 1.1);

      /* Quit button */
      button = gtk_button_new_with_label("Quit");
      gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 1);
      g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(button_clicked), NULL);
      g_signal_connect(G_OBJECT(canvas), "draw", G_CALLBACK(on_draw_event), image); 
    }
  }
  g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
  gtk_widget_show_all(window);

  gtk_main();

  cairo_surface_destroy((cairo_surface_t *)image);

  return 0;
}
