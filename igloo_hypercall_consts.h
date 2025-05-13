enum igloo_hypercall_constants {
    /* General operations */
    IGLOO_OPEN         = 100,
    IGLOO_IOCTL_ENOTTY = 105,
    
    /* Network-related operations */
    IGLOO_IPV4_SETUP   = 200,
    IGLOO_IPV4_BIND    = 201,
    IGLOO_IPV6_SETUP   = 202,
    IGLOO_IPV6_BIND    = 203,
    IGLOO_IPV4_RELEASE = 204,
    IGLOO_IPV6_RELEASE = 205,
    
    /* Hypervisor operations */
    IGLOO_HYP_UNAME    = 300,
    IGLOO_HYP_ENOENT   = 305,
    
    /* Task info operations */
    IGLOO_HYP_TASK_COMM    = 590,
    IGLOO_HYP_TASK_TGID    = 591,
    IGLOO_HYP_TASK_PTGID   = 592,
    IGLOO_HYP_TASK_STIME   = 593,
    IGLOO_HYP_TASK_KTHREAD = 594,
    IGLOO_HYP_KTHREAD_CHANGE = 595,
    IGLOO_HYP_THREAD_CHANGE  = 596,
    IGLOO_HYP_TASK_ARGV    = 597,
    IGLOO_HYP_TASK_ARGC    = 598,
    IGLOO_HYP_TASK_ENVV    = 599,
    IGLOO_HYP_TASK_ENVC    = 600,
    IGLOO_HYP_TASK_EUID    = 601,
    IGLOO_HYP_TASK_EGID    = 602,
    
    /* Task and VMA changes */
    HC_TASK_CHANGE     = 5900,
    HC_VMA_UPDATE      = 5910,
    IGLOO_HYP_VMA_REPORT_UPDATE = 5910,
    IGLOO_HYP_VMA_VM_START = 5911,
    IGLOO_HYP_VMA_VM_END   = 5912,
    IGLOO_HYP_VMA_NAME     = 5913,
    IGLOO_HYP_VMA_SPECIAL  = 5914,
    IGLOO_HYP_TASK_PSTIME  = 1595,
    
    /* Syscall operations */
    IGLOO_HYP_SETUP_SYSCALL  = 0x1337,
    IGLOO_HYP_SYSCALL_ENTER  = 0x1338,
    IGLOO_HYP_SYSCALL_RETURN = 0x1339,
    IGLOO_HYP_SETUP_TASK_COMM = 0x133a,
    IGLOO_HYP_OSI_TASK_SWITCH = 0x3337,
    
    /* Uprobe operations */
    IGLOO_HYP_UPROBE_ENTER  = 0x6901,
    IGLOO_HYP_UPROBE_RETURN = 0x6902,
    
    /* Miscellaneous operations */
    IGLOO_SIGSTOP_KTHREAD   = 0x0c6ea29a,
    IGLOO_HYPERFS_MAGIC     = 0x51ec3692, /* crc32("hyperfs") */
    IGLOO_SIGSTOP_ARGV      = 0xbae7babc,
    IGLOO_SIGSTOP_QUERY     = 0x7b7287d5,
    IGLOO_HYPER_REGISTER_MEM_REGION = 0xbebebebe,
    IGLOO_SYSCALL           = 0x6408400B
};