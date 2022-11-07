CC32 = i686-linux-gnu-gcc-9
CFLAGS32 = -g -march=i386 

CC = gcc
CFLAGS = -g  

LDFLAGS = -static

all: amd64_demo01 amd64_demo02 x86_demo01 x86_demo02

amd64_demo01: demo01.c
	$(CC) $(CFLAGS) -o $@ demo01.c $(LDFLAGS)

amd64_demo02: demo02.c
	$(CC) $(CFLAGS) -o $@ demo02.c $(LDFLAGS)

x86_demo01: demo01.c
	$(CC32) $(CFLAGS32) -o $@ demo01.c $(LDFLAGS)

x86_demo02: demo02.c
	$(CC32) $(CFLAGS32) -o $@ demo02.c $(LDFLAGS)

clean:
	rm -f amd64_demo01
	rm -f amd64_demo02
	rm -f x86_demo01
	rm -f x86_demo02
