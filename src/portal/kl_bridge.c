/*
 * kl_bridge.c -- host<->guest TCP streams over a guest-polled hypercall, for
 * vendor kernels without vsock (AF_VSOCK is 3.9+; 2.6.36's AF_MAX is 38).
 *
 * The host asks for a connection to an address inside the guest; a kernel
 * thread here opens it with an in-kernel socket and shuttles bytes. Nothing
 * runs in guest userspace, so loopback-only services and ports the guest
 * firewall drops from the LAN are reachable, the way vpnguin reaches them on
 * donor kernels. Wire protocol: igloo_bridge_proto.h.
 *
 * One thread owns every connection, so there is no locking. It polls the
 * host with one hypercall per pass. Idle, it sleeps until a bridged socket
 * has data or room (its sk callbacks kick the thread), or at most a jiffy
 * with a connection open (host->guest latency) and HZ/10 with none.
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <asm/io.h>
#include "hypercall.h"
#include "igloo_bridge_proto.h"

static int bridge = 1;
module_param(bridge, int, 0);
MODULE_PARM_DESC(bridge, "start the host<->guest TCP bridge thread (default 1)");

#define KB_NCONN 32

struct kb_conn {
    unsigned int id;
    struct socket *sock;
    unsigned char *pend;            /* host->guest bytes not yet written */
    unsigned int poff, plen;
    unsigned int host_win;          /* bytes we may still send to the host */
    unsigned int ack_owed;          /* written to the socket, not yet acked */
    int opened;                     /* G_OPENED to report: 1 + status */
    int status;
    int guest_eof;                  /* G_CLOSED sent */
    int host_eof;                   /* H_CLOSE received */
    int shut_wr;                    /* SHUT_WR done */
};

static struct kb_conn *kb_conns[KB_NCONN];
static DECLARE_WAIT_QUEUE_HEAD(kb_wq);
static int kb_kick;

/* the stock TCP callbacks, taken from the first bridged socket. sk_data_ready
 * lost its byte-count argument in 3.15. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
#define KB_DR_ARGS struct sock *sk, int n
#define KB_DR_CALL sk, n
#else
#define KB_DR_ARGS struct sock *sk
#define KB_DR_CALL sk
#endif
static void (*kb_o_data_ready)(KB_DR_ARGS);
static void (*kb_o_write_space)(struct sock *);
static void (*kb_o_state_change)(struct sock *);

static void kb_poke(void)
{
    kb_kick = 1;
    wake_up_interruptible(&kb_wq);
}

static void kb_data_ready(KB_DR_ARGS)
{
    kb_o_data_ready(KB_DR_CALL);
    kb_poke();
}

static void kb_write_space(struct sock *sk)
{
    kb_o_write_space(sk);
    kb_poke();
}

static void kb_state_change(struct sock *sk)
{
    kb_o_state_change(sk);
    kb_poke();
}

static void kb_hook(struct socket *sock, int on)
{
    struct sock *sk = sock->sk;

    write_lock_bh(&sk->sk_callback_lock);
    if (on) {
        if (!kb_o_data_ready) {
            kb_o_data_ready = sk->sk_data_ready;
            kb_o_write_space = sk->sk_write_space;
            kb_o_state_change = sk->sk_state_change;
        }
        /* only wrap the callbacks we can restore */
        if (sk->sk_data_ready == kb_o_data_ready &&
            sk->sk_write_space == kb_o_write_space &&
            sk->sk_state_change == kb_o_state_change) {
            sk->sk_data_ready = kb_data_ready;
            sk->sk_write_space = kb_write_space;
            sk->sk_state_change = kb_state_change;
        }
    } else if (sk->sk_data_ready == kb_data_ready) {
        sk->sk_data_ready = kb_o_data_ready;
        sk->sk_write_space = kb_o_write_space;
        sk->sk_state_change = kb_o_state_change;
    }
    write_unlock_bh(&sk->sk_callback_lock);
}
static unsigned char *kb_tx, *kb_rx;
static unsigned int kb_txlen;

static int kb_put(unsigned char type, unsigned char flags, unsigned int conn,
                  const void *payload, unsigned int len)
{
    struct igloo_bridge_rec *r;
    unsigned int need = sizeof(*r) + IGLOO_BRIDGE_ALIGN(len);

    if (kb_txlen + need > IGLOO_BRIDGE_BUF)
        return -ENOSPC;
    r = (struct igloo_bridge_rec *)(kb_tx + kb_txlen);
    r->type = type;
    r->flags = flags;
    r->len = len;
    r->conn = conn;
    if (len)
        memcpy(r + 1, payload, len);
    kb_txlen += need;
    return 0;
}

static unsigned int kb_tx_room(void)
{
    unsigned int used = kb_txlen + sizeof(struct igloo_bridge_rec);

    return used >= IGLOO_BRIDGE_BUF ? 0 : IGLOO_BRIDGE_BUF - used;
}

static struct kb_conn *kb_find(unsigned int id)
{
    int i;

    for (i = 0; i < KB_NCONN; i++)
        if (kb_conns[i] && kb_conns[i]->id == id)
            return kb_conns[i];
    return NULL;
}

static void kb_free(struct kb_conn *c)
{
    int i;

    for (i = 0; i < KB_NCONN; i++)
        if (kb_conns[i] == c)
            kb_conns[i] = NULL;
    if (c->sock) {
        kb_hook(c->sock, 0);
        sock_release(c->sock);
    }
    vfree(c->pend);
    kfree(c);
}

static void kb_open(unsigned int id, const struct igloo_bridge_open *o)
{
    struct sockaddr_in sin;
    struct timeval tv = { .tv_sec = 2 };
    struct kb_conn *c;
    int i, slot = -1, err;

    for (i = 0; i < KB_NCONN; i++)
        if (!kb_conns[i]) {
            slot = i;
            break;
        }
    c = kzalloc(sizeof(*c), GFP_KERNEL);
    if (c)
        c->pend = vmalloc(IGLOO_BRIDGE_WIN);
    if (slot < 0 || !c || !c->pend) {
        if (c) {
            vfree(c->pend);
            kfree(c);
        }
        err = -ENOMEM;
        kb_put(IGLOO_BRIDGE_G_OPENED, 0, id, &err, sizeof(err));
        return;
    }
    c->id = id;
    c->host_win = IGLOO_BRIDGE_WIN;
    kb_conns[slot] = c;

    err = o->proto == IPPROTO_TCP ? 0 : -EPROTONOSUPPORT;
    if (!err)
        err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &c->sock);
    if (!err) {
        /* bounds a blocking connect to an unreachable address */
        kernel_setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO,
                          (char *)&tv, sizeof(tv));
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = o->addr;
        sin.sin_port = o->port;
        err = kernel_connect(c->sock, (struct sockaddr *)&sin, sizeof(sin), 0);
    }
    c->opened = 1;
    c->status = err;
    if (err) {
        kb_put(IGLOO_BRIDGE_G_OPENED, 0, id, &err, sizeof(err));
        kb_free(c);
        return;
    }
    kb_hook(c->sock, 1);
    if (!kb_put(IGLOO_BRIDGE_G_OPENED, 0, id, &err, sizeof(err)))
        c->opened = 0;
}

/* Host bytes into the connection's queue; the host honours our window. */
static void kb_data(struct kb_conn *c, const unsigned char *p, unsigned int n)
{
    if (c->poff + c->plen + n > IGLOO_BRIDGE_WIN) {
        memmove(c->pend, c->pend + c->poff, c->plen);
        c->poff = 0;
    }
    if (c->plen + n > IGLOO_BRIDGE_WIN) {       /* host broke the window */
        kb_put(IGLOO_BRIDGE_G_CLOSED, IGLOO_BRIDGE_RST, c->id, NULL, 0);
        kb_free(c);
        return;
    }
    memcpy(c->pend + c->poff + c->plen, p, n);
    c->plen += n;
}

static void kb_rx_records(unsigned int len)
{
    unsigned int off = 0;

    while (off + sizeof(struct igloo_bridge_rec) <= len) {
        struct igloo_bridge_rec *r = (struct igloo_bridge_rec *)(kb_rx + off);
        unsigned char *p = (unsigned char *)(r + 1);
        struct kb_conn *c;

        if (off + sizeof(*r) + r->len > len)
            break;
        off += sizeof(*r) + IGLOO_BRIDGE_ALIGN(r->len);
        if (r->type == IGLOO_BRIDGE_H_OPEN) {
            if (r->len >= sizeof(struct igloo_bridge_open))
                kb_open(r->conn, (struct igloo_bridge_open *)p);
            continue;
        }
        c = kb_find(r->conn);
        if (!c)
            continue;                           /* already gone here */
        switch (r->type) {
        case IGLOO_BRIDGE_H_DATA:
            kb_data(c, p, r->len);
            break;
        case IGLOO_BRIDGE_H_ACK:
            if (r->len >= 4)
                c->host_win += *(unsigned int *)p;
            break;
        case IGLOO_BRIDGE_H_CLOSE:
            if (r->flags & IGLOO_BRIDGE_RST)
                kb_free(c);
            else
                c->host_eof = 1;
            break;
        }
    }
}

/* Guest socket -> tx records. Returns bytes moved. */
static int kb_pull(struct kb_conn *c)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
    struct igloo_bridge_rec *r;
    struct kvec iov;
    unsigned int room = kb_tx_room();
    int n;

    if (c->guest_eof || !c->host_win || room < 512)
        return 0;
    if (room > IGLOO_BRIDGE_CHUNK)
        room = IGLOO_BRIDGE_CHUNK;
    if (room > c->host_win)
        room = c->host_win;
    r = (struct igloo_bridge_rec *)(kb_tx + kb_txlen);
    iov.iov_base = r + 1;
    iov.iov_len = room;
    n = kernel_recvmsg(c->sock, &msg, &iov, 1, room, MSG_DONTWAIT);
    if (n == -EAGAIN)
        return 0;
    if (n <= 0) {
        if (!kb_put(IGLOO_BRIDGE_G_CLOSED, n ? IGLOO_BRIDGE_RST : 0,
                    c->id, NULL, 0))
            c->guest_eof = n ? 2 : 1;
        return 0;
    }
    r->type = IGLOO_BRIDGE_G_DATA;
    r->flags = 0;
    r->len = n;
    r->conn = c->id;
    kb_txlen += sizeof(*r) + IGLOO_BRIDGE_ALIGN(n);
    c->host_win -= n;
    return n;
}

/* Queued host bytes -> guest socket. Returns bytes moved. */
static int kb_push(struct kb_conn *c)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
    struct kvec iov;
    int n;

    if (!c->plen)
        return 0;
    iov.iov_base = c->pend + c->poff;
    iov.iov_len = c->plen;
    n = kernel_sendmsg(c->sock, &msg, &iov, 1, c->plen);
    if (n == -EAGAIN)
        return 0;
    if (n < 0) {
        c->plen = 0;
        if (!c->guest_eof &&
            !kb_put(IGLOO_BRIDGE_G_CLOSED, IGLOO_BRIDGE_RST, c->id, NULL, 0))
            c->guest_eof = 2;
        return 0;
    }
    c->poff += n;
    c->plen -= n;
    if (!c->plen)
        c->poff = 0;
    c->ack_owed += n;
    return n;
}

static int kb_thread(void *unused)
{
    unsigned long tx_pa = virt_to_phys(kb_tx), rx_pa = virt_to_phys(kb_rx);
    int i, attached = -1;

    while (!kthread_should_stop()) {
        unsigned long ret;
        int moved = 0, nconn = 0;

        kb_kick = 0;            /* a kick from here on ends the next sleep */

        /* outbound: acks first, then socket data */
        for (i = 0; i < KB_NCONN; i++) {
            struct kb_conn *c = kb_conns[i];

            if (!c)
                continue;
            nconn++;
            if (c->opened && !kb_put(IGLOO_BRIDGE_G_OPENED, 0, c->id,
                                     &c->status, 4))
                c->opened = 0;
            if (c->opened)
                continue;                       /* no data before OPENED */
            if (c->ack_owed && !kb_put(IGLOO_BRIDGE_G_ACK, 0, c->id,
                                       &c->ack_owed, 4))
                c->ack_owed = 0;
            moved += kb_pull(c);
        }

        ret = igloo_hypercall4(IGLOO_BRIDGE_HC, IGLOO_BRIDGE_MAGIC,
                               tx_pa, kb_txlen, rx_pa);
        if (ret == IGLOO_BRIDGE_MAGIC) {        /* no host side */
            if (attached != 0)
                printk(KERN_INFO "IGLOO: bridge: no host side, polling\n");
            attached = 0;
            kb_txlen = 0;
            schedule_timeout_interruptible(HZ);
            continue;
        }
        if (attached != 1)
            printk(KERN_INFO "IGLOO: bridge: host attached\n");
        attached = 1;
        kb_txlen = 0;
        if (ret > IGLOO_BRIDGE_BUF)
            ret = 0;
        kb_rx_records(ret);
        moved += ret;

        /* inbound: drain queues, then retire finished connections */
        for (i = 0; i < KB_NCONN; i++) {
            struct kb_conn *c = kb_conns[i];

            if (!c)
                continue;
            moved += kb_push(c);
            if (c->host_eof && !c->plen && !c->shut_wr) {
                kernel_sock_shutdown(c->sock, SHUT_WR);
                c->shut_wr = 1;
            }
            if (c->guest_eof == 2 ||
                (c->guest_eof && c->host_eof && !c->plen && !c->ack_owed))
                kb_free(c);
        }

        if (moved)
            cond_resched();
        else
            wait_event_interruptible_timeout(kb_wq,
                    kb_kick || kthread_should_stop(), nconn ? 1 : HZ / 10);
    }
    return 0;
}

int kl_bridge_init(void)
{
    struct task_struct *t;

    if (!bridge)
        return 0;
    kb_tx = (unsigned char *)__get_free_pages(GFP_KERNEL,
                                              get_order(IGLOO_BRIDGE_BUF));
    kb_rx = (unsigned char *)__get_free_pages(GFP_KERNEL,
                                              get_order(IGLOO_BRIDGE_BUF));
    if (!kb_tx || !kb_rx) {
        printk(KERN_ERR "IGLOO: bridge: no buffers\n");
        return 0;                               /* bridge is optional */
    }
    t = kthread_run(kb_thread, NULL, "igloo_bridge");
    if (IS_ERR(t))
        printk(KERN_ERR "IGLOO: bridge: kthread failed %ld\n", PTR_ERR(t));
    else
        printk(KERN_INFO "IGLOO: bridge: started (tx %lx rx %lx)\n",
               virt_to_phys(kb_tx), virt_to_phys(kb_rx));
    return 0;
}
