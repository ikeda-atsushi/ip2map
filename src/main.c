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
#include <signal.h>
#include <sys/select.h>
#include <GeoIP.h>
#include <cairo.h>
#include <errno.h>
#include <gtk/gtk.h>

#include "ip2loc.h"

#define Latt 0
#define Long 1

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

/* GEOIP data base */
static char * DB_CITY ="/usr/local/share/GeoIP/GeoLiteCity.dat";
/* Buffer size */
static int    BUF_SIZE = 2048;

/* link to socket discpritor */
SocketDesc  *__sdhead;
/*  GEO descpritor */
GeoIP       *__geo;
/* link to hold GEO info */
IP2Location *__ip2loc;
/* program name = argv[0] */
char        *__prog;


int             AnalyzePacket(u_char *data, int size);
void            mainWindow(void);
int             scan_packets(void);
static void     sigusr1_handler(int sig);
static void     sigusr2_handler(int sig);

extern SocketDesc *openRawSocket(int argc, char **dev, int promiscFlag, int ipOnly);

// SIGUSR1
static void
sigusr1_handler(int sig)
{
  fprintf(stdout, "signal USR1 called\n");
}

// SIGUSR2
static void
sigusr2_handler(int sig)
{
  fprintf(stdout, "signal USR2 called\n");
}

int
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
    fprintf(stderr, "%s: City data does not exist\n", __prog);
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

/* main */
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

  if ((sdp=openRawSocket(argc-1, argv, 0, 0))<0) {
    fprintf(stderr, "InitRawSocket:error:%s'n", argv[1]);
    GeoIP_delete(__geo);
    return (-1);
  }

  i=1;
  do {
    scan_packets();
  } while(i++<=100);

  mainWindow();

  gtk_main();

  return 0;
}
