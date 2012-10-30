CFILES = main.c http_server.c http_parser.c

obj-m += tkhttpd.o
tkhttpd-objs := $(CFILES:.c=.o)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
