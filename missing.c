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


/*
TODO:
defrag?

atomic_dec(&ct->ct_general.use); - nf_core:nf_conntrack_in: without this, conntrack entries don't expire, looks like i miss something

time.c: #if 0 around unnecessary parts, timeconst.h copied in
timer.c: elegge at kell irni (elejen tracing off, szemet ki)


modules need the following:

#undef module_init
#define module_init(x) void init_##x(){x();}
#undef module_exit
#define module_exit(x) void fini_##x(){x();}


/usr/src/linux-3.2.68/arch/x86/Makefile
ifdef CONFIG_CC_STACKPROTECTORxxx


-O0: /usr/src/linux-3.2.68/include/linux/rcupdate.h:798  build_bug_on needs to be commented out

*/

// MISC
void exit(int);
void panic(const char *fmt, ...) {
    exit(0);
}

struct tracepoint __tracepoint_module_get;

int __sched _cond_resched(void) {
    return 0;
}


unsigned long _copy_from_user(void *to, const void __user *from, unsigned  n) {
    memcpy(to, from, n);
    return 0;
}

unsigned long _copy_to_user(void *to, const void __user *from, unsigned  n) {
    memcpy(to, from, n);
    return 0;
}


struct module __this_module;
unsigned long totalram_pages = 800000;
int cpu_number = 0; // current cpu identifier, not counter


// ALLOC

void *malloc(size_t);
//#define malloc(x) (malloc(x+100))
void free(const void *);
void *calloc(size_t, size_t);
int sprintf(char *, const char *, ...);

void *__kmalloc(size_t size, gfp_t flags) {
    if(flags & __GFP_ZERO)
	return calloc(1, size);
    return malloc(size);
}

void kfree(const void *buf) {
    free(buf);
}

void *__kmalloc_node(size_t size, gfp_t flags, int node) {
    return malloc(size);
}


struct cache_sizes malloc_sizes[] = {
#define CACHE(x) { .cs_size = (x) },
#include <linux/kmalloc_sizes.h>
        CACHE(ULONG_MAX)
#undef CACHE
};


void vfree(const void *addr) {
    free(addr);
}

void *vmalloc(unsigned long size) {
    return malloc(size);
}

void *vmalloc_node(unsigned long size, int node) {
    return malloc(size);
}

void *vzalloc(unsigned long size) {
    return calloc(1, size);
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) {
    void *objp;

    objp = malloc(cachep->slab_size);
    if(cachep->ctor)
	cachep->ctor(objp);
    return objp;
}

void *kmem_cache_alloc_trace(size_t size, struct kmem_cache *cachep, gfp_t flags) {
    return malloc(size);
}

void *kmem_cache_alloc_node_trace(size_t size, struct kmem_cache *cachep, gfp_t flags, int node) {
    return malloc(size);
}

struct kmem_cache *
kmem_cache_create (const char *name, size_t size, size_t align,
         unsigned long flags, void (*ctor)(void *))
{
    struct kmem_cache *cachep;

    cachep = calloc(1, sizeof(*cachep));
    cachep->slab_size = size;
    cachep->ctor = ctor;
    cachep->name = name;
//    cachep->align = align;
    //list_add(&cachep->next, &cache_chain);
    return cachep;
}

void kmem_cache_destroy(struct kmem_cache *cachep) {
    // we should also destroy the cache itself
    printk("destroying cache %s\n", cachep->name);
    free(cachep);
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp) {
    free(objp);
}

void *kmem_cache_alloc_node(struct kmem_cache *cachep,
                                     gfp_t flags, int node)
{
     return kmem_cache_alloc(cachep, flags);
}

size_t malloc_usable_size (const void *ptr);
void *__krealloc(const void *p, size_t new_size, gfp_t flags) {
    void *ret;
    size_t ks;

    if(!p)
	return NULL;

    ks = malloc_usable_size(p);

    if(ks >= new_size)
	return (void *)p;

    ret = malloc(new_size);
    if(ret && p)
	memcpy(ret, p, ks);

    return ret;
}

unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order) {
    return (unsigned long)malloc(PAGE_SIZE * (1<<order));
}

void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot) {
    return malloc(size);
}

void free_pages(unsigned long addr, unsigned int order) {
    free((void*)addr);
}

void __percpu *__alloc_percpu(size_t size, size_t align) { // we should align this?
    return calloc(1, size);
}

void free_percpu(void __percpu *ptr) {
    free(ptr);
}

// LOCK
void __sched __mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key) {
}

void __sched mutex_lock(struct mutex *lock) {
    atomic_dec(&lock->count);
}

int __sched mutex_lock_interruptible(struct mutex *lock) {
    atomic_dec(&lock->count);
    return 0;
}

void __sched mutex_unlock(struct mutex *lock) {
    atomic_inc(&lock->count);
}

#ifdef CONFIG_SMP
void __lockfunc _raw_read_lock_bh(rwlock_t *lock) {
}

void __lockfunc _raw_read_unlock_bh(rwlock_t *lock) {
}

void __lockfunc _raw_spin_lock(raw_spinlock_t *lock) {
}

void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock) {
}

void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock) {
}

unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock) {
    return 0; // flags
}

void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags) {
}

void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock) {
}
#endif

void local_bh_disable(void) {
}

void local_bh_enable(void) {
}

// NET

// only used for fragmented skbs, and we don't use those
unsigned char *__pskb_pull_tail(struct sk_buff *skb, int delta) {
    return NULL;
}

// we also don't expand skbs
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp_mask) {
    *(char*)0 = 0;
    return 0;
}

void kfree_skb(struct sk_buff *skb) {
}

void synchronize_net(void) {
}

#if 0
struct net init_net = {
     .dev_base_head = LIST_HEAD_INIT(init_net.dev_base_head),
};
#endif

struct sk_buff *skb_gso_segment(struct sk_buff *skb, netdev_features_t features) {
    return NULL;
}

struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4, struct sock *sk) {
    return NULL;
}

unsigned int inet_addr_type(struct net *net, __be32 addr) {
    return RTN_UNICAST;
}

void dst_release(struct dst_entry *dst) {
}



// PROC
struct proc_dir_entry *proc_mkdir(const char *name, struct proc_dir_entry *parent) {
    struct proc_dir_entry *ret;

    ret = malloc(sizeof(*ret) + strlen(name) + 1);
    ret->parent = parent;
    strcpy(ret->name, name);
    printk("proc_mkdir: creating %s under %s\n", name, parent?parent->name:"/");
    return ret;
}


void listcon(void);
void listconsum(void);
void listfile(struct proc_dir_entry *);
struct proc_dir_entry *nf_conntrack, *nf_conntrack_sum;


void listcon(void) {
    listfile(nf_conntrack);
}

void listconsum(void) {
    listfile(nf_conntrack_sum);
}

void listfile(struct proc_dir_entry *pde) {
    struct file *f;
    char buf[1024];
    int r;
    loff_t ppos = 0;

    f = calloc(1, sizeof(*f));
    pde->proc_fops->open(NULL, f);

    while((r = pde->proc_fops->read(f, buf, sizeof(buf) - 1, &ppos)) > 0) {
	buf[r] = 0;
	printk("%s", buf);
    }
    pde->proc_fops->release(NULL, f);
    free(f);
}


struct proc_dir_entry *proc_create_data(const char *name, mode_t mode,
                                     struct proc_dir_entry *parent,
                                         const struct file_operations *proc_fops,
                                         void *data) {
    struct proc_dir_entry *ret;

    ret = malloc(sizeof(*ret) + strlen(name) + 1);
    strcpy(ret->name, name);
    ret->proc_fops = proc_fops;
    ret->data = data;
    printk("proc_create_data: creating %s under %s\n", name, parent?parent->name:"/");
    if(!strcmp(name, "nf_conntrack")) {
	nf_conntrack_sum = ret;
    }
    return ret;
}


int proc_dostring(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos) {
    return 0;
}

struct ctl_table_header *register_sysctl_paths(const struct ctl_path *path, struct ctl_table *table) {
    return (void*)1;
}

void proc_net_remove(struct net *net, const char *name) {
}

#include <linux/ctype.h>
const unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,                                /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,                 /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                                /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                                /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                            /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                                /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                                /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                                /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,              /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                                /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                                /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                                /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,              /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                                /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                                /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                                /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                        /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                        /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,    /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,        /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,        /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,        /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,        /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};       /* 240-255 */


int strnicmp(const char *s1, const char *s2, size_t len)
{
        /* Yes, Virginia, it had better be unsigned */
        unsigned char c1, c2;

        if (!len)
                return 0;

        do {
                c1 = *s1++;
                c2 = *s2++;
                if (!c1 || !c2)
                        break;
                if (c1 == c2)
                        continue;
                c1 = tolower(c1);
                c2 = tolower(c2);
                if (c1 != c2)
                        break;
        } while (--len);
        return (int)c1 - (int)c2;
}



int audit_enabled  = 0;
void audit_log_end(struct audit_buffer *ab) {
}
void audit_log_format(struct audit_buffer *ab, const char *fmt, ...) {
}
struct audit_buffer *audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type) {
    return (void*)1;
}


size_t strlcat(char *dest, const char *src, size_t count)
{
        size_t dsize = strlen(dest);
        size_t len = strlen(src);
        size_t res = dsize + len;

        /* This would be a bug */
        BUG_ON(dsize >= count);

        dest += dsize;
        count -= dsize;
        if (len >= count)
                len = count-1;
        memcpy(dest, src, len);
        dest[len] = 0;
        return res;
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
        size_t ret = strlen(src);

        if (size) {
                size_t len = (ret >= size) ? size - 1 : ret;
                memcpy(dest, src, len);
                dest[len] = '\0';
        }
        return ret;
}

int net_ratelimit() {
    static last;

    if(jiffies - last > 10000) {
	last = jiffies;
	return 1;
    }
    return 0;
}

int nr_cpu_ids = 1;

unsigned long __per_cpu_offset[NR_CPUS];

int vprintf(const char *format, va_list ap);
int printk(const char *fmt, ...) {
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = vprintf(fmt, ap);
    va_end(ap);
    return ret;
}

//int __put_user_2(void *ptr, unsigned int i) {
//    *(unsigned short*)ptr = i;
//}
/*
 * Strange magic calling convention: pointer in %ecx,
 * value in %eax(:%edx), return value in %eax. clobbers %rbx
 */
void __put_user_1(void) {}
void __put_user_2(void) {}
void __put_user_4(void) {}
void __put_user_8(void) {}
// put_user(void *to, [int,char,...]*from) ?


int __request_module(bool wait, const char *fmt, ...) {
    return -EINVAL;
}


int seq_open_net(struct inode *ino, struct file *f, const struct seq_operations *ops, int size) {
    return __seq_open_private(f, ops, size) != NULL; // do we have to free something later? cf put_net()
}

int seq_release_net(struct inode *ino, struct file *f) {
    return 0;
}

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len) {
    memcpy(to, skb->data + offset, len); // looks good - need to implement error handling
    return 0;
}

unsigned int __sw_hweight32(unsigned int w)
{
#ifdef ARCH_HAS_FAST_MULTIPLIER
        w -= (w >> 1) & 0x55555555;
        w =  (w & 0x33333333) + ((w >> 2) & 0x33333333);
        w =  (w + (w >> 4)) & 0x0f0f0f0f;
        return (w * 0x01010101) >> 24;
#else
        unsigned int res = w - ((w >> 1) & 0x55555555);
        res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
        res = (res + (res >> 4)) & 0x0F0F0F0F;
        res = res + (res >> 8);
        return (res + (res >> 16)) & 0x000000FF;
#endif
}

unsigned long __sw_hweight64(__u64 w)
{
#if BITS_PER_LONG == 32
        return __sw_hweight32((unsigned int)(w >> 32)) +
               __sw_hweight32((unsigned int)w);
#elif BITS_PER_LONG == 64
#ifdef ARCH_HAS_FAST_MULTIPLIER
        w -= (w >> 1) & 0x5555555555555555ul;
        w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
        w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;
        return (w * 0x0101010101010101ul) >> 56;
#else
        __u64 res = w - ((w >> 1) & 0x5555555555555555ul);
        res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
        res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
        res = res + (res >> 8);
        res = res + (res >> 16);
        return (res + (res >> 32)) & 0x00000000000000FFul;
#endif
#endif
}

#if 0
void unregister_pernet_subsys(struct pernet_operations *ops) {
}
#endif

bool capable(int cap) {
    return 1;
}

void *kmemdup(const void *src, size_t len, gfp_t gfp) {
    void *p;

    p = malloc(len);
    if(p)
	memcpy(p, src, len);
    return p;
}

struct task_struct *current_task; // should be initialized with &init_task, but it would be even better if we didn't use this at all
int numa_node;

int strtobool(const char *s, bool *res)
{
        switch (s[0]) {
        case 'y':
        case 'Y':
        case '1':
                *res = true;
                break;
        case 'n':
        case 'N':
//        case '': ??? TODO
                *res = false;
                break;
        default:
                return -EINVAL;
        }
        return 0;
}

/* Actually could be a bool or an int, for historical reasons. */
int param_set_bool(const char *val, const struct kernel_param *kp)
{
        /* No equals means "set"... */
        if (!val) val = "1";

        /* One of =[yYnN01] */
        return strtobool(val, kp->arg);
}
EXPORT_SYMBOL(param_set_bool);

int param_get_bool(char *buffer, const struct kernel_param *kp)
{
        /* Y and N chosen as being relatively non-coder friendly */
        return sprintf(buffer, "%c", *(bool *)kp->arg ? 'Y' : 'N');
}
EXPORT_SYMBOL(param_get_bool);

struct kernel_param_ops param_ops_bool = {
        .set = param_set_bool,
        .get = param_get_bool,
};

unsigned long kernel_stack;


int open(const char *pathname, int flags);
ssize_t read(int fd, void *buf, size_t count);
int close(int fd);


void get_random_bytes(void *buf, int nbytes) {
    int fd;

    fd = open("/dev/urandom", O_RDONLY); // proper random is deemed too slow
    read(fd, buf, nbytes);
    close(fd);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp);
ktime_t ktime_get_real(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return timespec_to_ktime(now);
}

//LIST_HEAD(net_namespace_list);

int
nla_policy_len(const struct nla_policy *p, int n)
{
    return 10000;
#if 0
        int i, len = 0;

        for (i = 0; i < n; i++, p++) {
                if (p->len)
                        len += nla_total_size(p->len);
                else if (nla_attr_minlen[p->type])
                        len += nla_total_size(nla_attr_minlen[p->type]);
        }

        return len;
#endif
}

int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data) {
    return 0; // notsupported
}

struct kernel_param_ops param_ops_uint;
int param_set_uint(const char *val, const struct kernel_param *kp) {
    return 0;
}
int param_get_uint(char *buffer, const struct kernel_param *kp) {
    return 0;
}

struct proc_dir_entry *proc_net_fops_create(struct net *net,
     const char *name, mode_t mode, const struct file_operations *fops)
{
    struct proc_dir_entry *ret;

    ret = malloc(sizeof(*ret) + strlen(name) + 1);
    strcpy(ret->name, name);
    ret->proc_fops = fops;
    printk("proc_net_fops_create: creating %s\n", name);
    if(!strcmp(name, "nf_conntrack")) {
	nf_conntrack = ret;
    }
    return ret;
}

int rand(void);
u32 random32() {
    return rand();
}

void rtnl_lock(void)
{
//     mutex_lock(&rtnl_mutex);
}

void rtnl_unlock(void)
{
     /* This fellow will unlock it for us. */
//     netdev_run_todo();
}


asmlinkage void __sched schedule(void) {
}

struct ctl_table_header *register_net_sysctl_table(struct net *net,
     const struct ctl_path *path, struct ctl_table *table)
{
    return (void*)1;
}

void unregister_net_sysctl_table(struct ctl_table_header *header) {
}

//unsigned long volatile __jiffy_data jiffies;

int proc_dointvec(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos) {
    return 0;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos) {
    return 0;
}

bool has_capability_noaudit(struct task_struct *t, int cap) {
    return 1;
}

int idle_cpu(int cpu) {
    return 1;
}

DECLARE_BITMAP(cpu_online_bits, CONFIG_NR_CPUS) __read_mostly;
const struct cpumask *const cpu_online_mask = to_cpumask(cpu_online_bits);

const char *kallsyms_lookup(unsigned long addr,
                            unsigned long *symbolsize,
                            unsigned long *offset,
                            char **modname, char *namebuf)
{
    return NULL;
}

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
}

void raise_softirq(unsigned int nr)
{
}

int proc_dointvec_minmax(struct ctl_table *table, int write,
                   void __user *buffer, size_t *lenp, loff_t *ppos) {
    return 0;
}

void remove_proc_entry(const char *name, struct proc_dir_entry *parent) {
}

void unregister_sysctl_table(struct ctl_table_header * header) {
}

static void xregister_ipi(void) {
}

static int xassign_irq_vector(int irq) {
}

static void xfree_irq_vector(int vector) {
}

static void xresend_irq(unsigned int vector) {
}

struct pv_irq_ops pv_irq_ops = {.save_fl.func = xregister_ipi, .irq_disable.func = xregister_ipi, .restore_fl.func = xregister_ipi, .irq_enable.func = xregister_ipi, .irq_disable.func = xregister_ipi};

void rcu_barrier(void) {
}

void security_release_secctx(char *secdata, u32 seclen) {
}

int security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen) {
    return 1;
}

char *skip_spaces(const char *str) {
        while (isspace(*str))
                ++str;
        return (char *)str;
}

int sprint_backtrace(char *buffer, unsigned long address) {
    return 0;
}

int sprint_symbol(char *buffer, unsigned long address) {
    return 0;
}

void warn_slowpath_null(const char *file, int line) {
    printk("slow path at %s:%i\n", file, line);
}

void warn_slowpath_fmt(const char *file, int line, const char *fmt, ...)
{
    printk("slow path at %s:%i %s\n", file, line, fmt);
}

int nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
               int len, const struct nla_policy *policy)
{
    return 0;
}

int ip_defrag(struct sk_buff *skb, u32 user) {
    return -ENOMEM; // TODO
}

__inline__ void ip_send_check(struct iphdr *iph)
{
     iph->check = 0;
     iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

char *d_path(const struct path *path, char *buf, int buflen) {
    strcpy(buf, "d_path (deleted)");
    return buf;
}

char *__d_path(const struct path *path,
            const struct path *root,
            char *buf, int buflen)
{
    strcpy(buf, "d_path (deleted)");
    return buf;
}

char *dentry_path(struct dentry *dentry, char *buf, int buflen) {
    strcpy(buf, "d_path (deleted)");
    return buf;
}

inline void rcu_barrier_bh(void) {
}

int get_nohz_timer_target(void) {
    return 0;
}

ktime_t hrtimer_get_next_event(void) {
    ktime_t ret = { .tv64 = KTIME_MAX };
    return ret; // TODO ?
}

void hrtimer_run_pending(void) {
}

void hrtimer_run_queues(void) {
}


unsigned int sysctl_timer_migration = 1;

int __read_mostly timer_stats_active;

#ifdef CONFIG_SMP
void wake_up_idle_cpu(int cpu) {
}
#endif

unsigned long this_cpu_off;

void __init init_timer_stats(void) {
}

void timer_stats_update_stats(void *timer, pid_t pid, void *startf,
                           void *timerf, char *comm,
                           unsigned int timer_flag) {
}

int __ref register_cpu_notifier(struct notifier_block *nb) {
    return 0;
}

void dump_stack(void) {
}

struct task_struct *find_task_by_vpid(pid_t vnr) {
    return NULL;
}
