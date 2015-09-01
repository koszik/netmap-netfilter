#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include "/root/netmap/iptables-1.4.14/include/linux/netfilter_ipv6/ip6_tables.h"
#include "/root/netmap/iptables-1.4.14/include/linux/netfilter_ipv4/ip_tables.h"


struct usock_req {
    int action;
    int level;
    int optlen;
    int optname;
};

int proto;

#define MIN(a,b) ((a)<(b)?(a):(b))

int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen) {
    struct usock_req req;
    int ret[2];

    req.action = 0;
    req.level = proto;
    req.optname = optname;
    req.optlen = *optlen;

    if(write(sockfd, &req, sizeof(req)) != sizeof(req))
	return -1;
    if(write(sockfd, optval, *optlen) != *optlen)
	return -1;
    if(read(sockfd, &ret, sizeof(ret)) != sizeof(ret))
	return -1;
    if(ret[0]) {
	errno = ret[0];
	return -1;
    }
    *optlen = MIN(*optlen, ret[1]);
    read(sockfd, optval, *optlen); // todo err
    return 0;
}


int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen) {
    struct usock_req req;
    int ret;

    req.action = 1;
    req.level = proto;
    req.optname = optname;
    req.optlen = optlen;

    if(write(sockfd, &req, sizeof(req)) != sizeof(req))
	return -1;
    if(write(sockfd, optval, optlen) != optlen)
	return -1;
    if(read(sockfd, &ret, sizeof(ret)) != sizeof(ret))
	return -1;
    if(proto == PF_INET6 && optname == IP6T_SO_SET_REPLACE) {
	const struct ip6t_replace *r = optval;
	read(sockfd, r->counters, sizeof(struct xt_counters) * r->num_counters);
    }
    if(proto == PF_INET && optname == IPT_SO_SET_REPLACE) {
	const struct ipt_replace *r = optval;
	read(sockfd, r->counters, sizeof(struct xt_counters) * r->num_counters);
    }
    if(ret) {
	errno = ret;
	return -1;
    }
    return 0;
}

#define socket_path "/tmp/nfctl"

int socket(int domain, int type, int protocol) {
    if(type == SOCK_RAW && protocol == IPPROTO_RAW) {
	int fd;
	struct sockaddr_un addr;
	proto = domain;

	if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	    return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, socket_path, sizeof(socket_path));

	if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
	    close(fd);
	    return -1;
	}
	return fd;
    }
    int (*original_socket)(int, int, int);
    original_socket = dlsym(RTLD_NEXT, "socket");
    return (*original_socket)(domain, type, protocol);
}

