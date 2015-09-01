#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/poll.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include <net/protocol.h>
#include <linux/skbuff.h>

#include <net/checksum.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <trace/events/skb.h>


__sum16 __skb_checksum_complete_head(struct sk_buff *skb, int len)
{
	__sum16 sum;

sum = 0;
//	sum = csum_fold(skb_checksum(skb, 0, len, skb->csum));
//	if (likely(!sum)) {
//		if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
//			netdev_rx_csum_fault(skb->dev);
//		skb->ip_summed = CHECKSUM_UNNECESSARY;
//	}
	return sum;
}
EXPORT_SYMBOL(__skb_checksum_complete_head);

__sum16 __skb_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete_head(skb, skb->len);
}
EXPORT_SYMBOL(__skb_checksum_complete);

