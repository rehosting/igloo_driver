#ifndef _IGLOO_DEBUG_H
#define _IGLOO_DEBUG_H

#include <linux/kernel.h>

// Debug logging configuration for each module
struct igloo_debug_config {
    bool portal;       // Enable debug for portal module
    bool uprobe;       // Enable debug for uprobe module
    bool vma;          // Enable debug for VMA tracking
    bool syscall;      // Enable debug for syscall tracking
    bool osi;          // Enable debug for OSI features
};

// Global debug configuration (defined in igloo_hc.c)
extern struct igloo_debug_config igloo_debug;

// Debug print macros for each module
#define igloo_debug_portal(fmt, ...) \
    do { if (igloo_debug.portal) pr_emerg("IGLOO-PORTAL: " fmt, ##__VA_ARGS__); } while (0)

#define igloo_debug_uprobe(fmt, ...) \
    do { if (igloo_debug.uprobe) pr_emerg("IGLOO-UPROBE: " fmt, ##__VA_ARGS__); } while (0)

#define igloo_debug_vma(fmt, ...) \
    do { if (igloo_debug.vma) pr_emerg("IGLOO-VMA: " fmt, ##__VA_ARGS__); } while (0)

#define igloo_debug_syscall(fmt, ...) \
    do { if (igloo_debug.syscall) pr_emerg("IGLOO-SYSCALL: " fmt, ##__VA_ARGS__); } while (0)

#define igloo_debug_osi(fmt, ...) \
    do { if (igloo_debug.osi) pr_emerg("IGLOO-OSI: " fmt, ##__VA_ARGS__); } while (0)

#endif /* _IGLOO_DEBUG_H */
