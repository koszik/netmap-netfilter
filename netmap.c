#include <poll.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>


void consume_packet(char *, int, int);
int sockopt_init();


void receiver(void)
{
	 struct	nm_desc	*d[2];
	 struct	pollfd fds[3];
	 u_char	*buf;
	 struct	nm_pkthdr h;

	 d[0] = nm_open("netmap:eth1", NULL, 0, 0);
	 d[1] = nm_open("netmap:eth1^", NULL, 0, 0);
	 fds[0].fd	= NETMAP_FD(d[0]);
	 fds[0].events  = POLLIN;
	 fds[1].fd	= NETMAP_FD(d[1]);
	 fds[1].events  = POLLIN;
	 fds[2].fd	= sockopt_init();
	 fds[2].events  = POLLIN;
	 for (;;) {
	    int i;
	    poll(fds, 3, -1);
	    for(i = 0; i < 2; i++) {
		if(!fds[i].revents) continue;
		while((buf = nm_nextpkt(d[i], &h))) {
		    if(consume_pkt(buf, h.len, i) == 1)
			nm_inject(d[1-i], buf, h.len);
		}
	    }
	    if(fds[2].revents) {
		sockopt_get();
	    }
         }
//	 nm_close(d);
}
