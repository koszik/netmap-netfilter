/*
 * Session handler to simulate soopt* and network communication
 * over a TCP socket, and also run the callbacks.
 */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <net/if.h>


#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>	/* timersub */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>	/* read() */
#include <signal.h>

#include "missing.h"
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

int ticks;	/* kernel ticks counter */
int hz = 5000;          /* default clock time */
long tick = 0;  /* XXX is this 100000/hz ? */
long long handled;

//int callout_startup(void);
//int callout_run(void);


/*
 * session description for event-based programming
 */
/* event-based session support */

static struct sess *all_sessions, *new_sessions;

struct sess *
new_session(int fd, handler_t *func, void *arg, enum flags_t flags)
{
	struct sess *desc;
	desc = calloc(1, sizeof(*desc));
	if (desc == NULL)
		return NULL;
	desc->fd = fd;
	desc->func = func;
	desc->arg = arg;
	desc->flags = flags;
	desc->next = new_sessions;
	new_sessions = desc;
	return desc;
}

/* remove deleted sessions, merge with new ones */
static void
merge_sessions(void)
{
	struct sess *cur, *prev, *tmp;

	for (prev = NULL, cur = all_sessions; cur; prev = cur, cur = tmp) {
		tmp = cur->next;
		if ( (cur->flags & WANT_DELETE) == 0)
			continue;
		if (prev)
			prev->next = cur->next;
		else
			all_sessions = cur->next;
		memset(cur, 0, sizeof(*cur));
		free(cur);
		cur = prev;
	}
	if (prev)
		prev->next = new_sessions;
	else		all_sessions = new_sessions;
	new_sessions = NULL;
}

/* set the fdset, return the fdmax+1 for select() */
int
set_sessions(fd_set *r, fd_set *w)
{
	struct sess *cur;
	int fd_max = -1;
	int count = 0,ready = 0;

	FD_ZERO(r);
	FD_ZERO(w);
	merge_sessions();
	for (cur = all_sessions; cur; cur = cur->next) {
		count++;
		if (cur->flags & WANT_RUN) {
			ND("WANT_RUN on session %p", cur);
			cur->flags &= ~WANT_RUN;
			cur->func(cur, cur->arg);
		}
		if (cur->flags & WANT_READ)
			FD_SET(cur->fd, r);
		if (cur->flags & WANT_WRITE)
			FD_SET(cur->fd, w);
		if (cur->flags & (WANT_WRITE|WANT_READ)) {
			ready ++;
			if (cur->fd > fd_max)
				fd_max = cur->fd;
		}
	}
	ND("%d session %d waiting", count, ready);
	return fd_max + 1;
}

int
run_sessions(fd_set *r, fd_set *w)
{
	struct sess *cur;

	for (cur = all_sessions; cur; cur = cur->next) {
		int fd = cur->fd;
		// fprintf(stderr, "%s sess %p\n", __FUNCTION__, cur);
		if (FD_ISSET(fd, r) || FD_ISSET(fd, w))
			cur->func(cur, cur->arg);
	}
	return 0;
}

void listcon();
unsigned long volatile  jiffies;

void run_timer_softirq(void *);
void rcu_process_callbacks(void *);
void rcu_sched_qs();

void
callout_run() {
    static time_t timev;

    run_timer_softirq(NULL);
    rcu_sched_qs();
    rcu_process_callbacks(NULL);
    if(timev + 5 < time(NULL)) {
	if(getenv("DEBUG"))
	    listcon();
	listconsum();
	timev = time(NULL);
    }
}

void
sigint() {
    exit(0);
}

/*
 * main program for ipfw kernel side when running an userspace emulation:
 * open a socket on which we receive requests from userland,
 * another socket for calls from the 'kernel' (simulating packet
 * arrivals etc), and then periodically run the tick handler.
 */
int
main(int argc, char *argv[])
{
	struct timeval t0;
	int i;
	int old_ticks;
	uint64_t callouts = 0, skipped = 0;

	gettimeofday(&t0, NULL);
	old_ticks = ticks = 0;
//	callout_startup();

	netmap_add_port(argv[2], netmap_add_port(argv[1], NULL));
	nfmain();
	signal(SIGINT, sigint);

	for (;;) {
		struct timeval now, delta = { 0, tick} ;
		int n;
		fd_set r, w;

		n = set_sessions(&r, &w);
//delta.tv_usec += 1;
		if(select(n, &r, &w, NULL, &delta) < 0)
		    continue;
		run_sessions(&r, &w);
		gettimeofday(&now, 0);
		timersub(&now, &t0, &delta);
		/* compute absolute ticks. */
		ticks = (delta.tv_sec * hz) + (delta.tv_usec * hz) / 21000000;
		if (old_ticks != ticks) {
			jiffies++;
			callouts++;
			callout_run();
			old_ticks = ticks;
		} else {
			skipped++;
		}
//		RD(1, "callouts %lu skipped %lu %lli", (u_long)callouts, (u_long)skipped, handled);
	}

	return 0;
}
