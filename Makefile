CFILES = main.c http_server.c http_parser.c \
         kmemcached.c storage.c interface.c hash.c \
	 libmp/protocol_handler.c libmp/binary_handler.c libmp/byteorder.c libmp/cache.c libmp/ascii_handler.c libmp/pedantic.c

obj-m += recaro.o
recaro-objs := $(CFILES:.c=.o)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
