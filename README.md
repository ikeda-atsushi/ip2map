ip2map
======

A geographic locator for IP address. It shows you the geographic locations of the computers that are sending packets on a map. 

DEPENDANCIES
============
You need libraries below:

libgtk-3, libgeoip, libcairo2

GeoIP City Database
===================

Get GeoipCity.dat at MAXMIND

$ wget -N http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
$ gunzip GeoLiteCity.dat.gz
$ mv GeoLiteCity.dat /usr/local/share/GeoIP/

Install
=======

# cd src
# make
# sudo make install

Run
===
# sudo ip2man eth0 


Known bugs
==========

- segfault 