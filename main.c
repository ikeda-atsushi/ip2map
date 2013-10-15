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

static char * DB_CITY ="/usr/share/GeoIP/GeoIPCity.dat";
static char * TMP_PNG = "tmp.png";

typedef struct SocketDesc {
  struct SocketDesc *next; 
  struct SocketDesc *preb;
  int desc;
} SocketDesc;

SocketDesc *sdhead;
double **geocode;
static GeoIP *geo;

static int NUMOFIP = 10;
static char *IP_FOWARD = "/proc/sys/net/ipv4/ip_forward";

static char *ABC       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char        *MARKER    = "markers=size:tiny%7Ccolor:blue%7Clabel:S%7C<LATI>,<LONG>";
static char *STATICMAP_BASE_URL = "https://maps.google.com/maps/api/staticmap?center=38.822591,-98.818363&zoom=0&size=400x200&maptype=terrain&sensor=false";

double    ** getCityFromIP(struct iphdr *iphdr);
SocketDesc * OpenRawSocket(int argc, char **dev, int promiscFlag, int ipOnly);
char       * ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int          turnOffIPforward(void);

static void 
button_clicked(GtkWidget *button, gpointer user_data)
{
  gtk_main_quit();
}


void
buildURL(char **url)
{
  int len, cnt;
  char tmp[128];
  char *c;

  tmp[0]='\0';
  len = 0;
  cnt = 0;
  do 
    {
      sprintf(tmp, "&markers=size:tiny|  color:blue|  label:%c|  %9.6f,%9.6f", ABC[cnt], geocode[cnt][Latt], geocode[cnt][Long]);
      len = strlen(*url);
      strcat(*url, tmp);
    } while(++cnt<NUMOFIP) ;

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

double **
getCityFromIP(struct iphdr *iphdr)
{
  int i, available;
  char *ip, *buf;
  u_char *ptr;
  GeoIPRecord *rec;

  rec = NULL;
  ptr = (u_char *)iphdr;
  available = 0;
  buf = malloc(80);
  ip = ip_ip2str(iphdr->saddr, buf, 80);

  if (is_privateIP(ip))  {
    free(buf);
    return (NULL);
  }

  if ((rec=GeoIP_record_by_addr(geo, ip)) == NULL) {
    fprintf(stderr, "error on getting geocode\n");
    free(buf);
    return (NULL);
  }

  ptr += sizeof(struct iphdr);

  //#ifdef GEOCODE
  fprintf(stdout, "===\n");
  fprintf(stdout, "IP         : %s\n", ip);
  fprintf(stdout, "Port       : %u\n", ntohs(((struct tcphdr *)ptr)->dest));
  fprintf(stdout, "Contry     : %s\n", rec->country_name);
  fprintf(stdout, "City       : %s\n", rec->city);
  fprintf(stdout, "Postal code: %s\n", rec->postal_code);
  fprintf(stdout, "Latitude   : %10.6f\n", rec->latitude);
  fprintf(stdout, "Longitude  : %10.6f\n\n", rec->longitude);
  //#endif

  for (i=0; i<NUMOFIP; i++) {
    if (geocode[i][Latt] == rec->latitude 
	&& geocode[i][Long] == rec->longitude) {
      break;
    } else if (geocode[i][Latt] == 0.0 
	  && geocode[i][Long] == 0.0) {
	available = 1;
	break;
    } 
  } // for

  if (available == 1) {
    geocode[i][Latt] = rec->latitude;
    geocode[i][Long] = rec->longitude;
  }

  GeoIPRecord_delete(rec);
  free(buf);
  return (geocode);
}

SocketDesc *
OpenRawSocket(int argc, char **dev, int promiscFlag, int ipOnly)
{
  int i, on, cnt, soc;
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  SocketDesc *sdp;

  cnt = argc;
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

      sdp = (SocketDesc *)malloc(sizeof(SocketDesc));
      if (sdhead==NULL) {
	// make a link head
	sdp->desc = soc;
	sdp->next = sdp;
	sdp->preb = sdp;
	sdhead = sdp;
      } else {
	sdp->next = sdhead->next;
	sdp->preb = sdhead;
	sdhead->next = sdp;
	(sdhead->preb==sdhead)?sdhead->preb=sdp:0;
	sdp->desc = soc;
      }
      
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

  return (sdp);
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

  static int BUF = 2048;

  if (argc <= 1) {
    fprintf(stderr, "Usage: %s dev1 [dev2 ...]\n", argv[0]);
    return (-1);
  }

#ifdef NOPRINT
  FILE *keep=NULL;
  FILE *fp;

  if ((fp=fopen("/dev/null", "w")) != NULL) {
    keep = stderr;
    stderr = fp;
  }
#endif
  
  gtk_init(&argc, &argv);

  if ((geo=GeoIP_open(DB_CITY, 0))==NULL) {
    fprintf(stderr, "error: GeoIPCity.dat does not exist\n");
    return (-1);
  }

  sdhead = NULL;
  if ((buf=(u_char *)malloc(BUF))==NULL) {
    perror("malloc");
    return(-1);
  }
  if ((geocode=(double **)calloc(NUMOFIP, sizeof(double **)))==NULL) {
    GeoIP_delete(geo);
    perror("Sufficient memory");
    return(-1);
  }

  for (i=0; i<NUMOFIP; i++) {
    if ((geocode[i] = (double *)calloc(2, sizeof(double *)))==NULL) {
      perror("Not enough memeory");
      GeoIP_delete(geo);
      return(-1);
    }
  }

  if ((URL=(char *)malloc(2048))==NULL) {
    perror("Not enoght memory");
    GeoIP_delete(geo);
    return (-1);
  }
  URL[0]='\0';

  // Disable IP foward
  /*  if (turnOffIPforward()<0){
    return(-1);
    }*/

  /* SIGUSR1のシグナルハンドラを設定 */
  signal(SIGUSR1, sigusr1_handler);

  /* SIGUSR2のシグナルハンドラを設定 */
  signal(SIGUSR2, sigusr2_handler);
  
  if ((sdp=OpenRawSocket(argc-1, argv, 0, 0))<0) {
    fprintf(stderr, "InitRawSocket:error:%s'n", argv[1]);
    free(buf);
    GeoIP_delete(geo);
    return (-1);
  }

  /* SIGUSR1のシグナルを設定 */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);

  while(i++<=320) {

    FD_ZERO(&readfds);
    sptr = sdhead;
    ndfd = 0;
    do {
      FD_SET(sptr->desc, &readfds);
      ndfd = max(ndfd, sptr->desc);
      sptr = sptr->next;
    } while (sptr != sdhead);

    /* SIGUSR2が来るまでselectはblockし続けます */
    /* SIGUSR1ではEINTRは返りません */
    n = pselect(ndfd+1, &readfds, NULL, NULL, NULL, &sigset);
    /*    if (n == -1 && errno == EINTR)
	  continue; */
    if (n < 0) {
      perror ("pselect()");
      GeoIP_delete(geo);
      exit (1);
    }
    
    mainp = sdhead;
    do {
      if (FD_ISSET(mainp->desc, &readfds)) {
	if ((size=read(mainp->desc, buf, BUF))<=0) {
	  if (size==0) break;
	  perror("read");
	  break;
	}

	AnalyzePacket(buf, size);

	/*
	printf("buildURL\n");
	buildURL(&URL);
	*/
	mainp = mainp->next;
      } while (mainp!=sdhead);
      mainp = mainp->next;
    } while (mainp != sdhead);
  } // while(1)

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

  for (i=0;i<NUMOFIP;i++) {

    fprintf(stdout, "Latitude   : %10.6f\n", geocode[i][Latt]);
    fprintf(stdout, "Longitude  : %10.6f\n\n", geocode[i][Long]);
    
    if (geocode[i][Latt] != 0.0 && geocode[i][Long] != 0.0) {
      sprintf(tmp, "&markers=size:tiny|  color:blue|  label:%c:|  %f,%f", ABC[i], geocode[i][Latt], geocode[i][Long]);
      strcat(rest, tmp);
      tmp[0]='\0';
    }
  } // for

  len = strlen(rest);
  for (c=rest;c-rest<=len;c++) {
    if (*c == '|') {
      c[0]='%';
      c[1]='7';
      c[2]='C';
    }
  } // for
  fprintf(stdout, "REST=%s\n", rest);
  curl_global_init(CURL_GLOBAL_ALL);

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

  sptr = sdhead;
  do {
    close(sdp->desc);
    sptr = sptr->next;
  } while (sptr != sdhead);
  free(buf);
  free(URL);

  GeoIP_delete(geo);

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

#ifdef NOPRINT
  if (keep !=NULL) {
    stderr = keep;
  }
  fclose(fp);
#endif

  gtk_main();

  return 0;
}
