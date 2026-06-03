#ifndef IGLOO_PORTAL_MMAP_H
#define IGLOO_PORTAL_MMAP_H

#include <linux/mm.h>

static inline pgprot_t igloo_mmap_phys_pgprot(pgprot_t prot)
{
#if defined(CONFIG_ARM64)
    /*
     * arm64 maps pgprot_noncached() as device memory. User-space string and
     * runtime helpers may issue unaligned accesses into mmap()ed pseudo-files,
     * and device mappings fault on those accesses before QEMU sees the MMIO.
     */
    return pgprot_writecombine(prot);
#else
    return pgprot_noncached(prot);
#endif
}

#endif
