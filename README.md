# netmap-netfilter

Code hacked together from netmap-ipfw and linux's netfilter.
Tested with debian's 3.2 kernel, debian's 1.4.14-3.1 iptables.

The following needs to be added to /lib/modules/3.2.0-4-amd64/build/include/generated/autoconf.h:
```
#undef CONFIG_NET_NS
#undef CONFIG_XFRM
#undef CONFIG_NF_CONNTRACK_PROC_COMPAT
#undef CONFIG_SMP
#undef CONFIG_MODULE_UNLOAD
#undef CONFIG_CC_STACKPROTECTOR
```

Remove CONFIG_CC_STACKPROTECTOR=y from /lib/modules/3.2.0-4-amd64/build/include/config/auto.conf

Compiling:

```
mkdir ~/netmap
cd ~/netmap
git clone https://github.com/luigirizzo/netmap
apt-get source iptables
git clone https://github.com/koszik/netmap-netfilter
cd netmap-netfilter
./link
```


Running:

```
./main netmap:eth1 netmap:eth1^
sh fw
./iptables -L -vnx
```

