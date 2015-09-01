
#include <stdio.h>
#include <stdlib.h>

int pktest(void);

void netfilter_init(void);
//void init_ipv4_netfilter_init(void);
void    init_xt_init(void);

void    init_ip6_tables_init(void);
void init_ip6table_filter_init(void);
void init_log_tg6_init(void);

void init_ip_tables_init(void);
void init_iptable_filter_init(void);
void init_iptable_mangle_init(void);
void init_iptable_raw_init(void);
void init_log_tg_init(void);

void    cpumask_init(void);
void idr_init_cache(void);
void net_ns_init(void);
void receiver(void);
void sockopt_init(void);

void init_nf_conntrack_standalone_init(void);
void init_ecn_mt_init(void);
void init_state_mt_init(void);
void init_length_mt_init(void);
void init_limit_mt_init(void);
void init_xt_ct_tg_init(void);
void init_tcpudp_mt_init(void);
void init_hashlimit_mt_init(void);
void init_notrack_tg_init(void);
void init_nf_conntrack_l3proto_ipv4_init(void);
void init_timers(void);
void init_conntrack_mt_init(void);

int
nfmain(void) {
    printf("main init\n");
    cpumask_init();
    init_timers();
    idr_init_cache();
    net_ns_init();
    netfilter_init();
//    init_ipv4_netfilter_init();
    init_xt_init();

    init_ip6_tables_init();
    init_ip6table_filter_init();
    init_log_tg6_init();

    init_ip_tables_init();
    init_iptable_filter_init();
    init_iptable_mangle_init();
    init_iptable_raw_init();
    init_log_tg_init();
    init_nf_conntrack_standalone_init();
    init_nf_conntrack_l3proto_ipv4_init();

    init_state_mt_init();
    init_limit_mt_init();
    init_length_mt_init();
    init_conntrack_mt_init();
    init_hashlimit_mt_init();
    init_tcpudp_mt_init();
    init_notrack_tg_init();
    init_ecn_mt_init();
    init_xt_ct_tg_init();

    sockopt_init();
//    receiver();

    return 0;
}
