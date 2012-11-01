#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/tcp.h>
#include "tkhttpd.h"
#include "kmemcached.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY ""                 \
	"HTTP/1.1 200 OK" CRLF                         \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 8" CRLF                       \
	"Connection: Close" CRLF                       \
	CRLF                                           \
	"200 OK" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY ""       \
	"HTTP/1.1 200 OK" CRLF                         \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 8" CRLF                       \
	"Connection: Keep-Alive" CRLF                  \
	CRLF                                           \
	"200 OK" CRLF
#define HTTP_RESPONSE_404 ""                       \
	"HTTP/1.1 404 Not Found" CRLF                  \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 15" CRLF                      \
	"Connection: Close" CRLF                       \
	CRLF                                           \
	"404 Not Found" CRLF
#define HTTP_RESPONSE_404_KEEPALIVE ""             \
	"HTTP/1.1 404 Not Found" CRLF                  \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 15" CRLF                      \
	"Connection: Keep-Alive" CRLF                  \
	CRLF                                           \
	"404 Not Found" CRLF
#define HTTP_RESPONSE_500 ""                       \
	"HTTP/1.1 500 Internal Server Error" CRLF      \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 27" CRLF                      \
	"Connection: Close" CRLF                       \
	CRLF                                           \
	"500 Internal Server Error" CRLF
#define HTTP_RESPONSE_500_KEEPALIVE ""             \
	"HTTP/1.1 500 Internal Server Error" CRLF      \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 27" CRLF                      \
	"Connection: Keep-Alive" CRLF                  \
	CRLF                                           \
	"500 Internal Server Error" CRLF
#define HTTP_RESPONSE_501 ""                       \
	"HTTP/1.1 501 Not Implemented" CRLF            \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 21" CRLF                      \
	"Connection: Close" CRLF                       \
	CRLF                                           \
	"501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE ""             \
	"HTTP/1.1 501 Not Implemented" CRLF            \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 21" CRLF                      \
	"Connection: KeepAlive" CRLF                   \
	CRLF                                           \
	"501 Not Implemented" CRLF
#define HTTP_RESPONSE_505                          \
	"HTTP/1.1 505 HTTP Version Not Supported" CRLF \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 32" CRLF                      \
	"Connection: Close" CRLF                       \
	CRLF                                           \
	"505 HTTP Version Not Supported" CRLF
#define HTTP_RESPONSE_505_KEEPALIVE                \
	"HTTP/1.1 505 HTTP Version Not Supported" CRLF \
	"Server: " MODULE_NAME "/" MODULE_REV CRLF     \
	"Content-Type: text/plain" CRLF                \
	"Content-Length: 32" CRLF                      \
	"Connection: KeepAlive" CRLF                   \
	CRLF                                           \
	"505 HTTP Version Not Supported" CRLF

#define CONTENT_TYPE "Content-Type: "
#define CONTENT_LENGTH "Content-Length: "

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 4096

#define STRANDSIZE(S) S, strlen(S)
#define STRAPPEND(X, S) do { memcpy(X, S, strlen(S)); X += strlen(S); } while (0)

struct http_header {
	char name[128];
	char value[1024];
};

struct http_request {
	struct socket *socket;
	struct socket *proxy_socket;
	enum http_method method;
	char request_url[128];
	int num_headers;
	enum { NONE=0, FIELD, VALUE } last_header_element;
	struct http_header headers[32];
	char *recv_buf;
	char *send_buf;
	int send_bufsize;
	int complete;
};

static int
http_server_recv (struct socket *sock, char *buf, size_t size) {
	mm_segment_t oldfs;
	struct iovec iov = {
		.iov_base = (void *)buf,
		.iov_len = size
	};
	struct msghdr msg = {
		.msg_name = 0,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};
	int length = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	length = sock_recvmsg(sock, &msg, size, msg.msg_flags);
	set_fs(oldfs);
	return length;
}

static int
http_server_send (struct socket *sock, const char *buf, size_t size, int more) {
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_flags = more ? MSG_MORE : 0
	};
	int length, done = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	while (done < size) {
		iov.iov_base = (void *)((char *)buf + done);
		iov.iov_len = size - done;
		length = sock_sendmsg(sock, &msg, iov.iov_len);
		if (length < 0) {
			printk(KERN_ERR MODULE_NAME ": write error: %d\n", length);
			break;
		}
		done += length;
	}
	set_fs(oldfs);
	return done;
}

static int
response_flush(struct http_request *request, int more) {
	int ret = http_server_send(request->socket,
			request->send_buf, request->send_bufsize, more);
	request->send_bufsize = 0;
	return ret;
}

static int
response_write(struct http_request *request, void *buf, size_t len, int more) {
	int ret;
	//printk("response_write: sendbuf=%p(%ld) buf=%p(%ld) more=%d\n",
	//       request->send_buf, request->send_bufsize, buf, len, more);
	if (len < 200 && len + request->send_bufsize < SEND_BUFFER_SIZE) {
		memcpy(request->send_buf + request->send_bufsize, buf, len);
		request->send_bufsize += len;
		if (more) {
			return 0;
		} else {
			return response_flush(request, more);
		}
	} else {
		ret = response_flush(request, 1);
		if (ret < 0) return ret;
		if (len < 200 && more) {
			memcpy(request->send_buf, buf, len);
			request->send_bufsize = len;
			return ret;
		} else {
			return http_server_send(request->socket, buf, len, more);
		}
	}
}

static int
response_printf(struct http_request *request, int more, const char *fmt, ...) {
	va_list args;
	int ret=0;
	if (SEND_BUFFER_SIZE - request->send_bufsize < 1024) {
		ret = response_flush(request, 1);
		if (ret < 0) return ret;
	}
	va_start(args, fmt);
	ret = vsprintf(request->send_buf + request->send_bufsize, fmt, args);
	va_end(args);
	request->send_bufsize += ret;
	if (!more) {
		return response_flush(request, 0);
	}
	return ret;
}


static int
response_from_item(item_t *item, struct http_request *request, int *keep_alive) {
	char *start, *p, *q, *end;
	char buf[128];
	char *w = buf;
	long nchunk;

	STRAPPEND(w, "HTTP/1.1 200 OK\r\n");

	start = p = item->data;
	end = start + item->size;

	// 1行目: content_type
	q = p;
	while (*q != '\r') {
		q++;
		if (q == end) {
			printk("BAD CACHE: %s\n", request->request_url);
			return 503;
		}
	}
	STRAPPEND(w, CONTENT_TYPE);
	memcpy(w, p, q-p); w += q-p;
	*w++ = '\r';
	*w++ = '\n';
	p = q = q + 2; // skip \r\n

	// 2行目チャンク数.
	nchunk = simple_strtol(p, &q, 10); p = q = q + 2;

	if (nchunk <= 0) {
		printk("BUG: nchunk=%ld\n", nchunk);
		return 503;
	}

	if (*keep_alive) {
		STRAPPEND(w, "Connection: keep-alive\r\n");
	}
	// こっから先は後戻りできない.
	response_write(request, buf, w-buf, 1);
	w = buf;
	if (nchunk == 1) {
		// simple response.
		// chunkサイズは chunked encoding にならって 16進
		long size = simple_strtol(p, &q, 16); p = q = q+2;
		response_printf(request, 1,
				"Content-Length: %ld\r\n\r\n", size);
		response_write(request, p, size, 0);
		return 0;
	}
	else {
		int cur;
		response_write(request,
				STRANDSIZE("Transfer-Encoding: chunked\r\n\r\n"), 1);

		for (cur=0; cur<nchunk; ++cur) {
			long size = simple_strtol(p, &q, 16);
			//printk("chunk size: %ld\n", size);
			p = q = q + 2;
			response_printf(request, 1, "%lx\r\n", size);
			response_write(request, p, size, 1);
			response_write(request, CRLF, 2, 1);
			p = q = q + size + 2;

			if (cur+1 < nchunk) {
				item_t *subitem;
				// TODO: SSIの入れ子に対応.
				while (*q != '\r') {
					q++;
				}
				subitem = get_item(p, q-p);
				//strncpy(buf, p, q-p);
				//buf[q-p] = '\0';
				//printk("loading '%s'\n", buf);
				p = q = q+2;
				if (subitem == NULL) {
					printk("can't load subitem.\n");
					continue;
				}
				//printk("ssi chunk size: %ld\n", subitem->size);
				response_printf(request, 1, "%lx\r\n", subitem->size);
				response_write(request, subitem->data, subitem->size, 1);
				response_write(request, CRLF, 2, 1);
				release_item(subitem);
			}
		}
		response_write(request, STRANDSIZE("0\r\n\r\n"), 0);
		return 0;
	}
}

static int
open_client_socket (const char *addr, ushort port, struct socket **res) {
	struct socket *sock;
	int err, opt = 1;
	struct sockaddr_in s;

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": sock_create_kern() failure, err=%d\n", err);
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
	s.sin_addr.s_addr = in_aton(addr);
	s.sin_port = htons(port);
	err = kernel_connect(sock, (struct sockaddr *) &s, sizeof(s), 0);
	if (err < 0) {
		printk(KERN_ERR MODULE_NAME ": kernel_connect() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	*res = sock;
	return 0;
}

static void
close_client_socket (struct socket *socket) {
	kernel_sock_shutdown(socket, SHUT_RDWR);
	sock_release(socket);
}

static int
redirect_response (struct http_request *request) {
	char buf[1500];
	int len;
	while (1) {
		len = http_server_recv(request->proxy_socket, buf, sizeof(buf));
		if (len <= 0) {
			break;
		}
		http_server_send(request->socket, buf, len, 1);
	}
	return 0;
}

static int
redirect_get_request (struct http_request *request) {
	char buf[1024];
	int err, len, count;
	if (!request->proxy_socket)	{
		err = open_client_socket("127.0.0.1", 8080, &request->proxy_socket);
		if (err < 0) {
			printk(KERN_ERR MODULE_NAME ": can't open client socket!\n");
			return 500;
		}
	}
	len = snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\n", request->request_url);
	http_server_send(request->proxy_socket, buf, len, 1);
	for (count = 0; count < request->num_headers; count++) {
		if (strcmp(request->headers[count].name, "Connection") == 0) {
			continue;
		}
		len = snprintf(buf, sizeof(buf), "%s: %s\r\n", request->headers[count].name, request->headers[count].value);
		http_server_send(request->proxy_socket, buf, len, 1);
	}
	http_server_send(request->proxy_socket, "Connection: Close\r\n\r\n", 21, 0);
	return redirect_response(request);
}

static int
do_get (struct http_request *request, int *keep_alive) {
	item_t *item = get_item(request->request_url, strlen(request->request_url));
	if (item) {
		int status = response_from_item(item, request, keep_alive);
		release_item(item);
		return status;
	}
	return redirect_get_request(request);
}

static int
do_post (struct http_request *request, int *keep_alive) {
	return redirect_response(request);
}

static int
http_server_response (struct http_request *request, int keep_alive) {
	char *response;
	int status;

	switch (request->method) {
	case HTTP_GET:
		status = do_get(request, &keep_alive);
		break;
	case HTTP_POST:
		status = do_post(request, &keep_alive);
		break;
	default:
		// 405 Method Not Allowed
		status = 405;
	}
	if (status == 0)
		return 0; //response has sent already.

	//TODO: ret が 0 以外の場合は、そのステータスコードに応じたデフォルトのレスポンスを返す.
	printk(KERN_INFO MODULE_NAME ": request_url = %s\n", request->request_url);
	if (request->method != HTTP_GET) {
		response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
	} else {
		response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY : HTTP_RESPONSE_200_DUMMY;
	}
	http_server_send(request->socket, response, strlen(response), 0);
	return 0;
}

static int
http_parser_callback_message_begin (http_parser *parser) {
	struct http_request *request = parser->data;
	request->method = 0;
	request->request_url[0]='\0';
	request->num_headers = 0;
	request->last_header_element = 0;
	request->send_bufsize = 0;
	request->complete = 0;
	return 0;
}

static int
http_parser_callback_request_url (http_parser *parser, const char *p, size_t len) {
	struct http_request *request = parser->data;
	strncat(request->request_url, p, len);
	return 0;
}

static int
http_parser_callback_header_field (http_parser *parser, const char *p, size_t len) {
	struct http_request *request = parser->data;
	if (request->last_header_element != FIELD) {
		request->num_headers++;
	}
	strncat(request->headers[request->num_headers - 1].name, p, len);
	request->last_header_element = FIELD;
	return 0;
}

static int
http_parser_callback_header_value (http_parser *parser, const char *p, size_t len) {
	struct http_request *request = parser->data;
	strncat(request->headers[request->num_headers - 1].value, p, len);
	request->last_header_element = VALUE;
	return 0;
}

static int
http_parser_callback_headers_complete (http_parser *parser) {
	struct http_request *request = parser->data;
	int err, len, count;
	char buf[1024];
	request->method = parser->method;
	if (request->method == HTTP_POST) {
		if (!request->proxy_socket)	{
			err = open_client_socket("127.0.0.1", 8080, &request->proxy_socket);
			if (err < 0) {
				printk(KERN_ERR MODULE_NAME ": can't open client socket!\n");
				return 0;
			}
		}
		len = snprintf(buf, sizeof(buf), "POST %s HTTP/1.1\r\n", request->request_url);
		http_server_send(request->proxy_socket, buf, len, 1);
		for (count = 0; count < request->num_headers; count++) {
			if (strcmp(request->headers[count].name, "Connection") == 0) {
				continue;
			}
			len = snprintf(buf, sizeof(buf), "%s: %s\r\n", request->headers[count].name, request->headers[count].value);
			http_server_send(request->proxy_socket, buf, len, 1);
		}
		http_server_send(request->proxy_socket, "Connection: Close\r\n\r\n", 21, 0);
	}
	return 0;
}

static int
http_parser_callback_body (http_parser *parser, const char *p, size_t len) {
	struct http_request *request = parser->data;
	if (request->method == HTTP_POST) {
		http_server_send(request->proxy_socket, p, len, 0);
	}
	return 0;
}

static int
http_parser_callback_message_complete (http_parser *parser) {
	struct http_request *request = parser->data;
	http_server_response(request, http_should_keep_alive(parser));
	if (request->proxy_socket) {
		kernel_sock_shutdown(request->proxy_socket, SHUT_RDWR);
		sock_release(request->proxy_socket);
		request->proxy_socket = NULL;
	}
	request->complete = 1;
	return 0;
}

static int
http_server_worker (void *arg) {
	struct socket *socket;
	int ret;
	struct http_parser parser;
	struct http_parser_settings setting = {
		.on_message_begin = http_parser_callback_message_begin,
		.on_url = http_parser_callback_request_url,
		.on_header_field = http_parser_callback_header_field,
		.on_header_value = http_parser_callback_header_value,
		.on_headers_complete = http_parser_callback_headers_complete,
		.on_body = http_parser_callback_body,
		.on_message_complete = http_parser_callback_message_complete
	};
	struct http_request *request;

	socket = (struct socket *)arg;
	allow_signal(SIGKILL);
	allow_signal(SIGTERM);
	request = kmalloc(sizeof(struct http_request), GFP_KERNEL);
	if (!request) {
		printk(KERN_ERR MODULE_NAME ": can't allocate memory!\n");
		return -1;
	}
	request->recv_buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
	if (!request->recv_buf) {
		kfree(request);
		printk(KERN_ERR MODULE_NAME ": can't allocate memory!\n");
		return -1;
	}
	request->send_buf = kmalloc(SEND_BUFFER_SIZE, GFP_KERNEL);
	if (!request->send_buf) {
		kfree(request->recv_buf);
		kfree(request);
		printk(KERN_ERR MODULE_NAME ": can't allocate memory!\n");
		return -1;
	}
	request->send_bufsize = 0;
	request->socket = socket;
	request->proxy_socket = NULL;
	http_parser_init(&parser, HTTP_REQUEST);
	parser.data = request;
	while (!kthread_should_stop()) {
		ret = http_server_recv(socket, request->recv_buf, RECV_BUFFER_SIZE - 1);
		if (ret <= 0) {
			if (ret) {
				printk(KERN_ERR MODULE_NAME ": recv error: %d\n", ret);
			}
			break;
		}
		http_parser_execute(&parser, &setting, request->recv_buf, ret);
		if (request->complete && !http_should_keep_alive(&parser)) {
			break;
		}
	}
	kernel_sock_shutdown(socket, SHUT_RDWR);
	sock_release(socket);
	if (request->proxy_socket) {
		kernel_sock_shutdown(request->proxy_socket, SHUT_RDWR);
		sock_release(request->proxy_socket);
	}
	kfree(request->send_buf);
	kfree(request->recv_buf);
	kfree(request);
	return 0;
}

int
http_server_daemon (void *arg) {
	struct http_server_param *param;
	struct socket *socket;
	int err;
	struct task_struct *worker;

	param = (struct http_server_param *)arg;
	allow_signal(SIGKILL);
	allow_signal(SIGTERM);
	while (!kthread_should_stop()) {
		int yes=1;
		err = kernel_accept(param->listen_socket, &socket, 0);
		if (err < 0) {
			if (signal_pending(current)) {
				break;
			}
			printk(KERN_ERR MODULE_NAME ": kernel_accept() error: %d\n", err);
			continue;
		}
		kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (void*)&yes, sizeof(yes));
		worker = kthread_run(http_server_worker, socket, MODULE_NAME);
		if (IS_ERR(worker)) {
			printk(KERN_ERR MODULE_NAME ": can't create more worker process\n");
			continue;
		}
	}
	return 0;
}

/* vim: set sw=8 ts=8 noexpandtab :*/
