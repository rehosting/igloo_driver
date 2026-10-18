/*
 * kl_ksyms.c -- kernel symbol addresses from the host, for a vendor kernel
 * that does not export kallsyms_lookup_name (CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS).
 *
 * The injector passes them as the module parameter
 *     ksyms=name@hexaddr;name@hexaddr;...
 * (addresses from the stock kernel's own kallsyms or a lifted profile), and the
 * Makefile maps kallsyms_lookup_name() to kl_ksym_lookup() in this profile, so
 * call sites stay as they are. A name the host did not send resolves to 0,
 * which every call site already treats as "not found".
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

static char *ksyms;
module_param(ksyms, charp, 0);
MODULE_PARM_DESC(ksyms, "kernel symbols from the host: name@hexaddr;...");

static int kl_hex(char c)                  /* hex_to_bin() is 2.6.35+ */
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c |= 0x20;
    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

unsigned long kl_ksym_lookup(const char *name);
unsigned long kl_ksym_lookup(const char *name)
{
    size_t n = strlen(name);
    const char *p = ksyms;

    while (p && *p) {
        const char *end = strchr(p, ';');
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if (len > n + 1 && p[n] == '@' && !strncmp(p, name, n)) {
            unsigned long addr = 0;
            const char *h = p + n + 1;

            for (; h < p + len; h++) {
                int d = kl_hex(*h);

                if (d < 0)
                    return 0;
                addr = (addr << 4) | d;
            }
            return addr;
        }
        p = end ? end + 1 : NULL;
    }
    return 0;
}
