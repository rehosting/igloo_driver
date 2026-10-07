#ifndef __IGLOO_MAILBOX_H__
#define __IGLOO_MAILBOX_H__

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/page.h>

/*
 * Hypercall mailbox: a per-CPU page, registered with the host by physical
 * address, that carries a hypercall's number, arguments, return value and
 * the physical addresses of any per-call buffers. The host reads and writes
 * only guest-physical memory, so an exit needs no vCPU register state at
 * all. That matters under arm64 KVM, where fetching that state costs one
 * ioctl per register. See DESIGN-mailbox.md in the kvmperf lane.
 *
 * Every field is in guest byte order. Every address the host follows is the
 * physical address of linear-map memory.
 */

/* SMCCC function ID of the arm64 KVM doorbell (mode 2). */
#define IGLOO_SMCCC_MAILBOX 0xC3001338UL

/* Transport modes, as returned by IGLOO_HYPER_REGISTER_MAILBOX. */
#define IGLOO_MB_OFF  0  /* registers only: the original ABI */
#define IGLOO_MB_HC   1  /* doorbell = the ordinary hypercall instruction */
#define IGLOO_MB_HVC  2  /* doorbell = hvc #0 with x0 = IGLOO_SMCCC_MAILBOX */

struct igloo_mailbox {
    u8  magic[8];       /* "IGLOOMB1" */
    u64 nr;             /* IGLOO hypercall number */
    u64 args[6];        /* the arguments, in the order of the register ABI */
    u64 ret;            /* written by the host; preset to args[0] */
    u64 region_pa;      /* portal region of this call, 0 if none */
    u64 event_pa;       /* bounce copy of a syscall_event + pt_regs, 0 if none */
    u64 event_len;
    u64 str_arg;        /* 1-based index of the argument whose string is in payload */
    u64 seq;            /* incremented on every call */
    u8  payload[];      /* one-shot data for this call */
};

#define IGLOO_MB_PAYLOAD_MAX (PAGE_SIZE - sizeof(struct igloo_mailbox))

extern int igloo_mb_mode;

static inline bool igloo_mb_enabled(void)
{
    return READ_ONCE(igloo_mb_mode) != IGLOO_MB_OFF;
}

/* Allocate and register the mailboxes. Leaves the mode at IGLOO_MB_OFF on any failure. */
int igloo_mailbox_init(void);

/* The portal-interrupt flag: in the shared page when the mailbox is on. */
u64 *igloo_mb_portal_interrupt(void);

unsigned long igloo_mb_call(unsigned long nr,
                            unsigned long a0, unsigned long a1,
                            unsigned long a2, unsigned long a3,
                            unsigned long region_pa,
                            unsigned long event_pa, unsigned long event_len,
                            const char *str, int str_arg);

#endif
