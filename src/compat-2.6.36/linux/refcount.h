/* 2.6.36 compat: refcount_t (4.11) over atomic_t */
#ifndef _KL_REFCOUNT_H
#define _KL_REFCOUNT_H
#include <asm/atomic.h>
typedef struct { atomic_t refs; } refcount_t;
#define REFCOUNT_INIT(n) { .refs = ATOMIC_INIT(n) }
static inline void refcount_set(refcount_t *r, int n) { atomic_set(&r->refs, n); }
static inline unsigned int refcount_read(const refcount_t *r) { return atomic_read(&r->refs); }
static inline void refcount_inc(refcount_t *r) { atomic_inc(&r->refs); }
static inline int refcount_dec_and_test(refcount_t *r) { return atomic_dec_and_test(&r->refs); }
static inline int refcount_inc_not_zero(refcount_t *r) { return atomic_inc_not_zero(&r->refs); }
#endif
