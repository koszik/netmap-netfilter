#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "glue.h"

#undef nf_hook
#define nf_hook(a, b, c, d, e, f) nf_hook_slow(a, b, c, d, e, f, INT_MIN)
int
consume_pkt(unsigned char *pkt, int len, int side) {
    static struct sk_buff sk;
    static struct net_device inside = {.name="inside"};
    static struct net_device outside = {.name="outside"};
    struct net_device *in, *out;
    struct sk_buff *skb = &sk;
    int ret;
    int ethproto, vlan = 0;
    int nfproto;
//    int d1 = NF_INET_LOCAL_OUT, d2 = NF_INET_POST_ROUTING;
    int d1 = NF_INET_PRE_ROUTING, d2 = NF_INET_POST_ROUTING;

//memset(skb, 0, sizeof(*skb)); // conntrack fails otherwise
    skb->nfct = NULL; // not anymore, this fixed it
    skb->head = skb->data = pkt;
    skb->data += ETH_HLEN;
    skb->len = len;
    skb->mac_header = 0;
    skb->dev = &in;
    ethproto = ntohs(eth_hdr(skb)->h_proto);

    if(ethproto == ETH_P_8021Q) {
	unsigned short *dot1q;
	dot1q = (void*)skb->data;
	vlan = ntohs(dot1q[0]);
	ethproto = ntohs(dot1q[1]);
	skb->data += 4;
    }

    skb->network_header = skb->data - skb->head;

    switch(ethproto) {
	case ETH_P_IPV6:
	    nfproto = NFPROTO_IPV6;
	    break;
	case ETH_P_IP:
	    nfproto = NFPROTO_IPV4;
//	    skb->transport_header = skb->network_header + ((struct iphdr*)skb_network_header(skb))->ihl * 4;
//	    skb->transport_header = (u8 *)ip_hdr(skb) - skb->head; //((struct iphdr*)skb_network_header(skb))->ihl * 4;
	    break;
	default:
	    return NF_ACCEPT;
    }

    in = &inside; out = &outside;
//    if(side) { d1 = NF_INET_PRE_ROUTING; d2 = NF_INET_LOCAL_IN; }
    if(side) { in = &outside; out = &inside; };

    ret = nf_hook(nfproto, d1, skb, in, out, NULL);

    if(unlikely(ret != NF_ACCEPT))
        return 0;

//    ret = nf_hook(nfproto, NF_INET_FORWARD, skb, NULL, NULL, NULL);

    if(unlikely(ret != NF_ACCEPT))
        return 0;

    ret = nf_hook(nfproto, d2, skb, in, out, NULL);
    return ret == NF_ACCEPT;
}

// skb_network_offset(skb) + ip_hdrlen(skb), 
/*
 NF_INET_PRE_ROUTING,
 NF_INET_LOCAL_IN,
 NF_INET_FORWARD,
 NF_INET_LOCAL_OUT,
 NF_INET_POST_ROUTING,
 NF_INET_NUMHOOKS
*/
    
/*

nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT, skb, NULL,
                         skb_dst(skb)->dev, dst_output);

nf_hook_thresh(NFPROTO_IPV6, NF_INET_LOCAL_OUT, skb, NULL,
                         skb_dst(skb)->dev, dst_output, INT_MIN);

static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
                              struct sk_buff *skb,
                              struct net_device *indev,
                              struct net_device *outdev,
                              int (*okfn)(struct sk_buff *), int thresh)
 {
         if (nf_hooks_active(pf, hook))
                 return nf_hook_slow(pf, hook, skb, indev, outdev, okfn, thresh);
         return 1;
 }

 nf_hook_slow

*/