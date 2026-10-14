/* 2.6.36 compat: kuid/kgid (3.5) are plain ids here */
#include <linux/types.h>
#ifndef _KL_UIDGID
#define _KL_UIDGID
typedef uid_t kuid_t;
typedef gid_t kgid_t;
#define __kuid_val(u) (u)
#define __kgid_val(g) (g)
#define from_kuid(ns,u) (u)
#define from_kgid(ns,g) (g)
#endif
