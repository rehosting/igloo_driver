EXTRA_CFLAGS += -g -fno-reorder-functions

obj-m := igloo.o

# EXTRA_LDFLAGS += --print-map

# OLD (problematic on older kernels):
# PORTAL_SRCS := $(filter-out portal/portal_tramp_gen.c, $(wildcard portal/*.c))
# PORTAL_OBJS := $(PORTAL_SRCS:.c=.o)

# NEW: use $(src) so wildcard works when Makefile is parsed from kernel tree (Linux 4.x compatibility)
PORTAL_SRCS := $(filter-out $(src)/portal/portal_tramp_gen.c, $(wildcard $(src)/portal/*.c))
PORTAL_OBJS := $(patsubst $(src)/%.c,%.o,$(PORTAL_SRCS))

igloo-objs += igloo_hc.o hooks/syscalls_hc.o hooks/ioctl_hc.o \
        hooks/sock_hc.o hooks/uname_hc.o hooks/block_mounts.o \
		hooks/igloo_open.o \
		hyperfs/hyperfs.o \
		$(PORTAL_OBJS)

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ARCH ?= x86_64
CROSS_COMPILE ?=
EXTRA_CFLAGS += -I$(srctree)/drivers/igloobase \
			 -I$(PWD)/ \
			 -I$(PWD)/portal \
			 -I$(PWD)/hyperfs \
			 -I$(PWD)/hooks
PORTAL_TRAMP_GEN := portal/portal_tramp_gen.h

$(PORTAL_TRAMP_GEN): ../scripts/gen_portal_tramp.py
	python3 $< > $@

all: $(PORTAL_TRAMP_GEN)
	make -j$(nproc) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
