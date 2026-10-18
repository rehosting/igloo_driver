/*
 * kl_sock_ops.c -- socket bind/release reporting on a kernel without igloo's
 * socket hooks.
 *
 * A donor kernel calls igloo_sock_bind() after a successful bind and
 * igloo_sock_release() from sock_release(), through the igloo_sock_*_module
 * pointers its patches add. A faithful vendor kernel has neither pointer, so
 * sock_hc_init() falls back to this file: it wraps .bind and .release in the
 * inet and inet6 stream/dgram proto_ops tables and calls the same two
 * functions from hooks/sock_hc.c. The hypercalls are therefore identical to a
 * donor kernel's, and so are their semantics: a bind is reported once it has
 * succeeded, and a release whenever the socket's last reference goes -- an
 * explicit close, process exit, a fatal signal, or the last of several
 * processes sharing the socket after a fork.
 *
 * The tables are const but live in writable memory on the kernels this
 * targets (no CONFIG_DEBUG_RODATA). Every inet socket points at one of these
 * tables, so sockets that already exist are covered too. Faithful igloo.ko is
 * never unloaded (see igloo_hc.c), so the wrappers are never removed. A table
 * kallsyms can't name (text-only kallsyms, or no kallsyms_lookup_name export)
 * is taken from a throwaway kernel socket of its family and type.
 *
 * Built only with CONFIG_IGLOO_KL_SOCK; full builds compile every portal/
 * source by wildcard, hence the guard.
 */
#ifdef KL_HAVE_SOCK
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <net/net_namespace.h>

void igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address);
void igloo_sock_release(struct socket *sock);
int kl_sock_ops_init(void);

static const char *const kl_sock_names[] = {
    "inet_stream_ops", "inet_dgram_ops", "inet6_stream_ops", "inet6_dgram_ops",
};
#define KL_SOCK_N ((int)ARRAY_SIZE(kl_sock_names))

static struct proto_ops *kl_sock_tabs[KL_SOCK_N];
static int (*kl_sock_bind_orig[KL_SOCK_N])(struct socket *, struct sockaddr *, int);
static int (*kl_sock_release_orig[KL_SOCK_N])(struct socket *);

/* Which hooked table this socket's ops are; the wrappers are installed only in
 * those tables, so a socket that reaches one always matches. */
static int kl_sock_index(const struct socket *sock)
{
    int i;

    for (i = 0; i < KL_SOCK_N; i++)
        if (sock->ops == kl_sock_tabs[i])
            return i;
    return -1;
}

static int kl_sock_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    int i = kl_sock_index(sock);
    int ret;

    if (i < 0)
        return -EINVAL;
    ret = kl_sock_bind_orig[i](sock, uaddr, addr_len);
    /* uaddr is the kernel's sockaddr_storage copy (sys_bind / socketcall). */
    if (ret == 0)
        igloo_sock_bind(sock, (struct sockaddr_storage *)uaddr);
    return ret;
}

static int kl_sock_release(struct socket *sock)
{
    int i = kl_sock_index(sock);

    if (i < 0)
        return 0;
    igloo_sock_release(sock);          /* before sk is torn down */
    return kl_sock_release_orig[i](sock);
}

/* The table a fresh kernel socket of this family/type points at: the address
 * of inet_stream_ops & co. without a symbol table (text-only kallsyms, or none). */
static const struct { int family, type; } kl_sock_probe[KL_SOCK_N] = {
    { PF_INET, SOCK_STREAM }, { PF_INET, SOCK_DGRAM },
    { PF_INET6, SOCK_STREAM }, { PF_INET6, SOCK_DGRAM },
};

static struct proto_ops *kl_sock_ops_probe(int i)
{
    struct socket *sock = NULL;
    struct proto_ops *ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    if (sock_create_kern(&init_net, kl_sock_probe[i].family,
                         kl_sock_probe[i].type, 0, &sock) < 0)
#else
    if (sock_create_kern(kl_sock_probe[i].family, kl_sock_probe[i].type, 0,
                         &sock) < 0)
#endif
        return NULL;
    ops = (struct proto_ops *)sock->ops;
    sock_release(sock);
    return ops;
}

int kl_sock_ops_init(void)
{
    int i, n = 0;

    for (i = 0; i < KL_SOCK_N; i++) {
        struct proto_ops *ops =
            (struct proto_ops *)kallsyms_lookup_name(kl_sock_names[i]);

        if (!ops)
            ops = kl_sock_ops_probe(i);

        if (!ops || !ops->bind || !ops->release) {
            printk(KERN_INFO "IGLOO: kl_sock_ops: %s not found, not hooked\n",
                   kl_sock_names[i]);
            continue;
        }
        kl_sock_bind_orig[i] = ops->bind;
        kl_sock_release_orig[i] = ops->release;
        kl_sock_tabs[i] = ops;
    }
    smp_wmb();          /* originals and tables visible before any wrapper */
    for (i = 0; i < KL_SOCK_N; i++) {
        if (!kl_sock_tabs[i])
            continue;
        kl_sock_tabs[i]->bind = kl_sock_bind;
        kl_sock_tabs[i]->release = kl_sock_release;
        n++;
    }
    smp_wmb();
    printk(KERN_INFO "IGLOO: kl_sock_ops: bind/release hooked in %d proto_ops "
           "tables (no igloo_sock_*_module in this kernel)\n", n);
    return 0;
}
#endif /* KL_HAVE_SOCK */
