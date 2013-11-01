#ifndef __IP2LOC__
#define __IP2LOC__

#include <GeoIPCity.h>

typedef struct IP2Location {
  struct IP2Location *next;
  struct IP2Location *preb;
  GeoIPRecord        *geoip;
  double     latitude;
  double     longitude;
  u_int32_t  saddr;
  int        port;
  int        marker;
} IP2Location;

typedef struct SocketDesc {
  struct SocketDesc *next; 
  struct SocketDesc *preb;
  int desc;
} SocketDesc;


#endif
