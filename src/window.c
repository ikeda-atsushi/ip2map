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

#include <math.h>
#include <gtk/gtk.h>
#include <glib-object.h>

#include "ip2loc.h"

/* scale of map image*/
static double IMAGE_SCALE=0.38;

/* map image tmp file */
static char * MAP_PNG = "fig_world_e2.png";

extern IP2Location *__ip2loc;
extern SocketDesc  *__sdhead;
extern GeoIP       *__geo;

static void      rescan_clicked(GtkWidget *button, gpointer drawing_area);
static void      do_drawing_image(cairo_t *, cairo_surface_t *);
static gboolean  on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data);
static void      quit_clicked(GtkWidget *button, gpointer user_data);
static void      put_marker_on_image(cairo_t *cr, double x, double y);

void             checkLink(void);

extern int       scan_packets(void);
extern int       port_in_use(int port);
extern char     *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);

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
static void 
put_marker_on_image(cairo_t *cr, double x, double y)
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


void
mainWindow(void)
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

  return;
}

