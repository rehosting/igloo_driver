#ifndef HYPERCALL_H
#define HYPERCALL_H

#include <linux/types.h>
#include "ehypercall.h"

static inline unsigned long igloo_hypercall(unsigned long num,
                                            unsigned long arg1)
{
    return igloo_hypercall4(num, arg1, 0, 0, 0);
}

static inline unsigned long igloo_hypercall2(unsigned long num,
                                             unsigned long arg1,
                                             unsigned long arg2)
{
    return igloo_hypercall4(num, arg1, arg2, 0, 0);
}

static inline unsigned long igloo_hypercall3(unsigned long num,
                                             unsigned long arg1,
                                             unsigned long arg2,
                                             unsigned long arg3)
{
    return igloo_hypercall4(num, arg1, arg2, arg3, 0);
}

#endif
