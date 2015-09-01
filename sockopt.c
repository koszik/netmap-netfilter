#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <net/if.h>

#include "/root/netmap/iptables-1.4.14/include/linux/netfilter_ipv6/ip6_tables.h"
#include "/root/netmap/iptables-1.4.14/include/linux/netfilter_ipv4/ip_tables.h"

#include "netmap/missing.h"

struct usock_req {
    int action;
    int level;
    int optlen;
    int optname;
};


static int fd;

//int sockopt_init();
//int nf_setsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt, unsigned int len);
//int nf_getsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt, int *len);
int nf_setsockopt(void *sk, unsigned char pf, int val, char *opt, unsigned int len);
int nf_getsockopt(void *sk, unsigned char pf, int val, char *opt, int *len);

#define socket_path "/tmp/nfctl"

int sockopt_get(struct sess *sess, void *x) {
    struct usock_req req;
    int s = sess->fd;


    if(read(s, &req, sizeof(req)) != sizeof(req)) {
	sess->flags = WANT_DELETE;
	close(s);
	return 0;
    }

    void *sk = malloc(1024);
    {
	void *buf = malloc(req.optlen);
	int r = 0;
	while(r < req.optlen) {
	    int ret = read(s, buf + r, req.optlen - r);
	    if(ret < 0) {
		close(s);
		free(buf);
		free(sk);
		return;
	    }
	    r += ret;
	}
	if(req.action == 0) {
	    int ret[2];
	    ret[1] = req.optlen;
	    ret[0] = -nf_getsockopt(sk, req.level, req.optname, buf, &ret[1]);
	    if(ret[0] < 0) {
		printf("ret was %i, sending 0 instead\n", ret[0]);
		ret[0] = 0;
	    }
	    write(s, &ret, sizeof(ret));
	    if(!ret[0])
		write(s, buf, ret[1]);
	} else {
	    char *mb;
	    if(req.level == PF_INET6 && req.optname == IP6T_SO_SET_REPLACE) {
	        struct ip6t_replace *r = buf;
		r->counters = malloc(sizeof(struct xt_counters) * r->num_counters);
	    }
	    if(req.level == PF_INET && req.optname == IPT_SO_SET_REPLACE) {
	        struct ipt_replace *r = buf;
		r->counters = malloc(sizeof(struct xt_counters) * r->num_counters);
	    }
	    int ret = -nf_setsockopt(sk, req.level, req.optname, buf, req.optlen);
	    write(s, &ret, sizeof(ret));
	    if(req.level == PF_INET6 && req.optname == IP6T_SO_SET_REPLACE) {
	        struct ip6t_replace *r = buf;
	        write(s, r->counters, sizeof(struct xt_counters) * r->num_counters);
		free(r->counters);
	    }
	    if(req.level == PF_INET && req.optname == IPT_SO_SET_REPLACE) {
	        struct ipt_replace *r = buf;
	        write(s, r->counters, sizeof(struct xt_counters) * r->num_counters);
		free(r->counters);
	    }
	}
	free(buf);
    }
    free(sk);
//    close(s);
    return 0;
}



int sockopt_accept(struct sess *sess, void *x) {
    int s;

    s = accept(sess->fd, NULL, NULL);
    new_session(s, sockopt_get, NULL, WANT_READ);
    return 0;
}



int sockopt_init() {
    struct sockaddr_un addr;

    signal(SIGPIPE, SIG_IGN);
    unlink(socket_path);
    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, sizeof(socket_path));

    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
	close(fd);
	return -1;
    }
    listen(fd, 5);

    new_session(fd,  sockopt_accept, fd, WANT_READ);
}
