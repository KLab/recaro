#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include "tkhttpd.h"
#include "kmemcached.h"

#define DEFAULT_PORT 80
#define DEFAULT_PROC 20
#define DEFAULT_BACKLOG 100

static ushort port = DEFAULT_PORT;
module_param(port, ushort, S_IRUGO);
static ushort proc = DEFAULT_PROC;
module_param(proc, ushort, S_IRUGO);
static ushort backlog = DEFAULT_BACKLOG;
module_param(backlog, ushort, S_IRUGO);

struct socket *listen_socket;
struct http_server_param param;
struct task_struct *http_server;

static int
open_listen_socket (ushort port, ushort backlog, struct socket **res) {
	struct socket *sock;
	int err, opt = 1;
	struct sockaddr_in s;

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": sock_create_kern() failure, err=%d\n", err);
		return err;
	}
	opt = 1;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1;
	err = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 0;
	err = kernel_setsockopt(sock, SOL_TCP, TCP_CORK, (char *)&opt, sizeof(opt));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1024 * 1024;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof(opt));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1024 * 1024;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&opt, sizeof(opt));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = htonl(INADDR_ANY);
	s.sin_port = htons(port);
	err = kernel_bind(sock, (struct sockaddr *)&s, sizeof(s));
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_bind() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	err = kernel_listen(sock, backlog);
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_listen() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	*res = sock;
	return 0;
}

static void
close_listen_socket (struct socket *socket) {
	kernel_sock_shutdown(socket, SHUT_RDWR);
	sock_release(socket);
}

int __init
tkhttpd_init (void) {
	int err;

	err = open_listen_socket(port, backlog, &listen_socket);
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": can't open listen socket\n");
		return err;
	}
	param.listen_socket = listen_socket;
	param.proc = proc;
	http_server = kthread_run(http_server_daemon, &param, MODULE_NAME);
	if (IS_ERR(http_server)) {
		printk(KERN_ERR MODULE_NAME ": can't start http server daemon\n");
		close_listen_socket(listen_socket);
		return PTR_ERR(http_server);
	}

	return kmemcached_init();
}

void __exit
tkhttpd_exit (void) {
	send_sig(SIGTERM, http_server, 1);
	kthread_stop(http_server);
	close_listen_socket(listen_socket);
	kmemcached_exit();
	printk(KERN_INFO MODULE_NAME ": module unloaded\n");
}

module_init(tkhttpd_init);
module_exit(tkhttpd_exit);

MODULE_DESCRIPTION("Tiny Kernel module based HTTP Daemon.");
MODULE_AUTHOR("Masaya YAMAMOTO <yamamoto-ma@klab.com>");
MODULE_LICENSE("Dual BSD/GPL");

/* vim: set ts=8 sw=8 noexpandtab : */
