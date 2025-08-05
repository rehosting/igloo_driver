ccflags-y += -g -fno-reorder-functions
obj-m := igloo.o

# EXTRA_LDFLAGS += --print-map

PORTAL_SRCS := $(filter-out portal/portal_tramp_gen.c, $(wildcard portal/*.c))
PORTAL_OBJS := $(PORTAL_SRCS:.c=.o)

igloo-objs += igloo_hc.o hooks/syscalls_hc.o hooks/ioctl_hc.o \
        hooks/sock_hc.o hooks/uname_hc.o hooks/block_mounts.o \
		hooks/igloo_open.o \
		hyperfs/hyperfs.o \
		$(PORTAL_OBJS)

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ARCH ?= x86_64
CROSS_COMPILE ?=
ccflags-y += -I$(srctree)/drivers/igloobase \
			 -I${CURDIR}/ \
			 -I${CURDIR}/portal \
			 -I${CURDIR}/hyperfs \
			 -I${CURDIR}/hooks
PORTAL_TRAMP_GEN := portal/portal_tramp_gen.h

$(PORTAL_TRAMP_GEN): ../scripts/gen_portal_tramp.py
	python3 $< > $@

all: $(PORTAL_TRAMP_GEN)
	make -j$(nproc) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
