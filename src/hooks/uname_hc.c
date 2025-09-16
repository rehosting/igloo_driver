#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "hypercall.h"
#include "igloo.h"
#include <linux/binfmts.h>
#include <trace/syscall.h>
#include <linux/utsname.h>
#include "igloo_hypercall_consts.h"

void igloo_hc_newuname(struct new_utsname *name);

static void make_igloo_utsname(char *buf, struct new_utsname *name){
	char *token, *str;
	char *array[6];

	str = kstrdup(buf, GFP_KERNEL);

	int i = 0;
	while ((token = strsep(&str, ",")) != NULL){
		array[i] = kstrdup(token, GFP_KERNEL);

		if (strcmp(array[i], "none") == 0) {
			i++;
			continue;
		}

		if (i == 0)
			memcpy(name->sysname, array[i], sizeof(char) * 65);
		else if (i == 1)
			memcpy(name->nodename, array[i], sizeof(char) * 65);
		else if (i == 2)
			memcpy(name->release, array[i], sizeof(char) * 65);
		else if (i == 3)
			memcpy(name->version, array[i], sizeof(char) * 65);
		else if (i == 4)
			memcpy(name->machine, array[i], sizeof(char) * 65);
		else if (i == 5)
			memcpy(name->domainname, array[i], sizeof(char) * 65);

		i += 1;
	}
}

/**
 * Called from newuname in kernel/sys.c
 */
void igloo_hc_newuname(struct new_utsname *name){
	int i, rv, idx, x;
	char buf[395];
    for (i = 0; i < 10; i++) {
	    rv = igloo_hypercall2(IGLOO_HYP_UNAME, (unsigned long)&buf, 0);
	    if (rv != 0xDEADBEEF)
		    break;
        
        // probably unnecessary
	    x = 0;
	    for (idx = 0; idx < sizeof(buf); idx++) {
		    x += (int)buf[idx];
	    }
    }
	if (rv == 1)
		make_igloo_utsname(buf, name);
	if (rv == 0xDEADBEEF)
		printk_once(KERN_INFO "Failed to create custom igloo utsname string");
}

int uname_hc_init(void);
int uname_hc_init(void)
{
	void (**newuname_mod_ptr)(struct new_utsname *);
    printk(KERN_EMERG "IGLOO: Initializing uname hypercalls\n");
    newuname_mod_ptr = (void (**)(struct new_utsname *))kallsyms_lookup_name("igloo_hc_newuname_module");
    if (newuname_mod_ptr) {
        *newuname_mod_ptr = igloo_hc_newuname;
        printk(KERN_INFO "IGLOO: Set igloo_hc_newuname_module via kallsyms\n");
    } else {
        printk(KERN_ERR "IGLOO: Failed to find igloo_hc_newuname_module symbol via kallsyms\n");
    }
    return 0;
}