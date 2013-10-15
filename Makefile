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
