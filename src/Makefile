ccflags-y += -g
obj-m := igloo.o

# EXTRA_LDFLAGS += --print-map

PORTAL_SRCS := $(wildcard portal/*.c)
PORTAL_OBJS := $(PORTAL_SRCS:.c=.o)

igloo-objs += igloo_hc.o vma_hc.o syscalls_hc.o exec_hc.o ioctl_hc.o \
        open_hc.o sock_hc.o uname_hc.o block_mounts.o osi_hc.o \
        kprobe_syscalls.o \
		$(PORTAL_OBJS)

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ARCH ?= x86_64
CROSS_COMPILE ?=
ccflags-y := -I$(srctree)/drivers/igloo

all:
	make -j$(nproc) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
