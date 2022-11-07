CC = m68k-linux-gnu-gcc
CFLAGS = -g -march=68000 -mtune=68000
LDFLAGS = -static

all: m68k_demo01 m68k_demo02

m68k_demo01: demo01.c
	$(CC) $(CFLAGS) -o $@ demo01.c $(LDFLAGS)

m68k_demo02: demo02.c
	$(CC) $(CFLAGS) -o $@ demo02.c $(LDFLAGS)

clean:
	rm -f m68k_demo01
	rm -f m68k_demo02
