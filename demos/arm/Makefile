CC = arm-linux-gnueabi-gcc-9
CFLAGS = -g 
LDFLAGS = -static

all: arm_demo02

arm_demo02: demo02.c
	$(CC) $(CFLAGS) -o $@ demo02.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o $@_thumb demo02.c -mthumb $(LDFLAGS)

clean:
	rm -f arm_demo02
	rm -f arm_demo02_thumb
