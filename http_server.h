#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <linux/types.h>
#include <net/sock.h>

struct http_server_param {
	struct socket *listen_socket;
	unsigned short proc;
};

extern int
http_server_daemon (void *arg);

#endif
