 #######################################################################################################################
 #
 # ip2map :  This program shows you the locations of the computers that are sending packets to your computer on a map.  
 # Copyright (C) 2013 Atsushi Ikeda: ikeda.atsushi@gmail.com							        
 # 														        
 # This program is free software; you can redistribute it and/or						        
 # modify it under the terms of the GNU General Public License							        
 # as published by the Free Software Foundation; either version 2						        
 # of the License, or (at your option) any later version.							        
 # 														        
 # This program is distributed in the hope that it will be useful,						        
 # but WITHOUT ANY WARRANTY; without even the implied warranty of						        
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						        
 # GNU General Public License for more details.									        
 #														        
 # You should have received a copy of the GNU General Public License						        
 # along with this program; if not, write to the Free Software							        
 # Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.				        
 #
 #######################################################################################################################

CC  = /usr/bin/cc
LDLIBS = `pkg-config --libs gtk+-3.0` -lGeoIP -lcurl
CFLAGS = -g -Wall `pkg-config --cflags gtk+-3.0`
PROG = ip2map
SRCS = main.c \
	analyze.c \
	checksum.c \
	print.c
OBJS = ${SRCS:%.c=%.o}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} -o ${PROG} ${OBJS} ${LDLIBS}

.c.o: ${SRCS}
	${CC} ${INCLUDE} ${CFLAGS} -c $<

clean:
	${RM} -f ${PROG} ${OBJS} tmp.png *~

print:
	echo ${OBJS}
