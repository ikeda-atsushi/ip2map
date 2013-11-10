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
#include <math.h>
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
//#include <GeoIPCity.h>
#include <cairo.h>
#include <gtk/gtk.h>
#include <glib-object.h>
#include <errno.h>

#include "ip2loc.h"

#define Latt 0
#define Long 1

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

SocketDesc *__sdhead;
static GeoIP *__geo;

IP2Location *__ip2loc;

typedef struct polacd {
  double dlong;
  double dlati;
  double dr;
} polacd;

typedef struct xyz {
  double x;
  double y;
  double z;
} xyz;


/* GEOIP data base */
static char * DB_CITY ="/usr/share/GeoIP/GeoIPCity.dat";
/* map image tmp file */
static char * MAP_PNG = "fig_world_e2.png";

/* number of IP address */
static char *IP_FOWARD = "/proc/sys/net/ipv4/ip_forward";

/* program name = argv[0] */
static char *__prog;

/* scale of map image*/
static double IMAGE_SCALE=0.38;

/* Buffer size */
static int BUF_SIZE = 2048;

void            pol2xy(xyz *xyzp, polacd *cdp);
int             AnalyzePacket(u_char *data, int size);
int             turnOffIPforward(void);
int             port_in_use(int port);
char           *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
IP2Location    *getCityFromIP(struct iphdr *iphdr);
SocketDesc     *OpenRawSocket(int argc, char **dev, int promiscFlag, int ipOnly);
static void     do_drawing_image(cairo_t *, cairo_surface_t *);
static gboolean on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data);
static void     quit_clicked(GtkWidget *button, gpointer user_data);
static int      scan_packets(void);
static void     put_marker_on_image(cairo_t *cr, double x, double y);

void checkLink(void);

void
checkLink(void)
{
  IP2Location *ip;

  ip = __ip2loc;

  do {
    fprintf(stdout, "0x%x ->  ", (unsigned int)ip);
    ip=ip->next;
  } while(ip!=__ip2loc);

  printf("\n\n");

  return;
}

char *
ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
  struct in_addr *addr;

  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return (buf);
}


/* Rescan event */
static void
rescan_clicked(GtkWidget *button, gpointer drawing_area)
{
  int i;

  i=1;;
  do {
    scan_packets();
  } while (i++<=20);

  /* Re-draw window */
  gtk_widget_queue_draw(GTK_WIDGET(drawing_area));

  return;
}

/* Quit button event */
static void 
quit_clicked(GtkWidget *button, gpointer user_data)
{
  SocketDesc *sptr;

  /* close socket */
  sptr = __sdhead;
  do {
    close(sptr->desc);
    sptr = sptr->next;
  } while (sptr != __sdhead);

  GeoIP_delete(__geo);
  gtk_main_quit();

  return;
}

/* polacd to xy */
void 
pol2xy(xyz *xyzp, polacd *cdp)
{
  
  if (  -180.0 <= cdp->dlong && cdp->dlong < -30.0) {
    xyzp->x = 4.7 * cdp->dlong + 2030;
  } else if (-30.0 <= cdp->dlong && cdp->dlong <= 180.0) {
    xyzp->x = 4.7 * cdp->dlong + 338;
  }

  xyzp->y = -4.7 * cdp->dlati + 534;
  xyzp->z = 0;

  return;
}

/* put markers on map */
static void put_marker_on_image(cairo_t *cr, double x, double y)
{
  /* radius */
  double radius = 10.0;
  /* begining angle of a cercle in radian */
  double angle1 = 0.0  * (M_PI/180.0);  
  /* ending angle of a cercle in radian */
  double angle2 = 3600.0 * (M_PI/180.0); 

  cairo_set_source_rgb(cr, 1.0, 0.0,  0.0);
  cairo_set_line_width (cr, 10.0);
  cairo_arc (cr, x, y, radius, angle1, angle2);
  cairo_fill(cr);

  return;
}

/* Draw a png file */
static gboolean 
on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer image)
{
  do_drawing_image(cr, (cairo_surface_t *)image);

  return FALSE;
}

static void 
do_drawing_image(cairo_t *cr, cairo_surface_t *image)
{
  IP2Location *ip, *hold;

  /* expand, shurink of image */
  cairo_scale(cr, IMAGE_SCALE, IMAGE_SCALE);
  /* put a image on serface */
  cairo_set_source_surface(cr, image, 10, 10);
  cairo_paint(cr);    

  checkLink();

  /* Run __ip2loc to make markers on map */
  ip=__ip2loc;
  do { 
    polacd cdp;
    xyz  xy;

    if (ip &&  ip->port != -1 ) {

      if (port_in_use(ip->port)==0) {
	/* unlink IP2Location */
	if (!ip->preb) {
	  fprintf(stdout, "assartion: preb\n");
	  abort();
	}
	if (!ip->next) {
	  fprintf(stdout, "assartion: next\n");
	  abort();
	}

	if (ip == __ip2loc) {
	  __ip2loc = ip->preb;
	}
	hold = ip->preb;
	ip->preb->next = ip->next;
	ip->next->preb = ip->preb;
	GeoIPRecord_delete(ip->geoip);
	free(ip);
	ip = hold;
      } else {
 
	if (ip->marker) {
	  char buf[16];

	  fprintf(stdout, "IP         : [%s]\n", ip_ip2str(ip->saddr, buf, sizeof(buf)));
	  fprintf(stdout, "Port       : %d\n", ip->port);
	  fprintf(stdout, "Latitude   : %10.6f\n", ip->latitude);
	  fprintf(stdout, "Longitude  : %10.6f\n", ip->longitude);
	  fprintf(stdout, "Marker     : %d\n", ip->marker);
	  buf[0]='\0';
	  cdp.dlati = ip->latitude;
	  cdp.dlong = ip->longitude;
	  cdp.dr = 270.245093;
	  pol2xy(&xy, &cdp);

	  fprintf(stdout, "(x, y)     : x=%f, y=%f\n\n", xy.x, xy.y);
	  put_marker_on_image(cr, xy.x,  xy.y);
	}
      }
    }
    ip=ip->next;
  } while(ip!=__ip2loc);

  return;
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

static int
scan_packets(void)
{
  int n, ndfd, size;
  u_char *buf;
  fd_set readfds;
  SocketDesc *sptr, *mainp;
  sigset_t sigset;

  buf = malloc(BUF_SIZE);
  
  /* register SIGUSR1 */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);

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

  free(buf);

  return(0);
}
/* scan_packets */

int
init(void)
{

  /* register a signal handler on SIGUSR1 */
  signal(SIGUSR1, sigusr1_handler);

  /* register a signal handler on SIGUSR2 */
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

int
main(int argc, char **argv)
{
  int  i;
  SocketDesc *sdp;

  __prog = argv[0];

  if (argc <= 1) {
    fprintf(stderr, "Usage: %s dev1 [dev2 ...]\n", __prog);
    return (-1);
  }

  init();

  gtk_init(&argc, &argv);

  if ((sdp=OpenRawSocket(argc-1, argv, 0, 0))<0) {
    fprintf(stderr, "InitRawSocket:error:%s'n", argv[1]);
    GeoIP_delete(__geo);
    return (-1);
  }

  i=1;
  do {
    scan_packets();
  } while(i++<=20);/* while */

 {
   GtkWidget *window;
   GtkWidget *box;
   GtkWidget *canvas;

    /* drawing a map on window */
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_add(GTK_CONTAINER(window), box);

    canvas = gtk_drawing_area_new();
    {
      GtkWidget *Quit;
      GtkWidget *Rescan;
      GtkWidget *image;
      
      image = (GtkWidget *)cairo_image_surface_create_from_png(MAP_PNG);

      /* widget for image */
      gtk_box_pack_start(GTK_BOX(box), canvas, TRUE, TRUE, 1);

      gtk_window_set_title(GTK_WINDOW(window), "IP locator");

      gtk_widget_set_size_request(window, cairo_image_surface_get_width((cairo_surface_t *)image) * IMAGE_SCALE,
              cairo_image_surface_get_height((cairo_surface_t *)image) * IMAGE_SCALE); 

      /* Rescan button */
      Rescan = gtk_button_new_with_label("Rescan");
      gtk_box_pack_start(GTK_BOX(box), Rescan, FALSE, FALSE, 1);
      /* Quit button */
      Quit = gtk_button_new_with_label("Quit");
      gtk_box_pack_start(GTK_BOX(box), Quit, FALSE, FALSE, 1);

      /* connect signa and event */
      /* Quit button */
      g_signal_connect(G_OBJECT(Quit), "clicked", G_CALLBACK(quit_clicked), NULL);
      /* Rescan button */
      g_signal_connect(G_OBJECT(Rescan), "clicked", G_CALLBACK(rescan_clicked), canvas);

      /* Close window */
      g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
      /* Draw map */
      g_signal_connect(G_OBJECT(canvas), "draw", G_CALLBACK(on_draw_event), image); 
    }
    gtk_widget_show_all(window);
  }

  gtk_main();

  return 0;
}
