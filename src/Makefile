EXTRA_CFLAGS += -g -fno-reorder-functions
src ?= $(PWD)

obj-m := igloo.o

# --- Faithful-rehost profile (see src/Kconfig) ------------------------------
# In-tree builds read these from the kernel .config. Out-of-tree faithful builds
# (kernelsmith buildModule) cannot see this module's Kconfig, so they pass the
# symbols on the make command line, e.g.
#   make ... CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS=y
# Either way we mirror each selected symbol into a -D define so the C sources can
# #ifdef on it regardless of where it came from. Command-line variables
# propagate through MAKEFLAGS to the inner kbuild pass, so object selection below
# is consistent across both passes of a wrapper build.
# NO_KALLSYMS implies FAITHFUL, and (by default) the OSI-minimal object set.
# Use := (not ?=): a bare `?=` would DEFINE the var as empty and defeat a later
# `?= y`. A command-line CONFIG_IGLOO_OSI_MINIMAL=n still wins here, because
# command-line assignments override a makefile := (so the minimal set can be
# opted out of even under NO_KALLSYMS). An unset symbol compares as empty in the
# ifeq tests below, which is the intended "off".
ifeq ($(CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS),y)
  CONFIG_IGLOO_FAITHFUL := y
  CONFIG_IGLOO_OSI_MINIMAL := y
endif

ifeq ($(CONFIG_IGLOO_FAITHFUL),y)
  EXTRA_CFLAGS += -DCONFIG_IGLOO_FAITHFUL=1
endif
ifeq ($(CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS),y)
  EXTRA_CFLAGS += -DCONFIG_IGLOO_FAITHFUL_NO_KALLSYMS=1
endif
ifeq ($(CONFIG_IGLOO_OSI_MINIMAL),y)
  EXTRA_CFLAGS += -DCONFIG_IGLOO_OSI_MINIMAL=1 -fno-stack-protector
endif

# Faithful builds have no drivers/igloobase in the vendor kernel tree, so the
# base API headers (igloo.h, igloo_syscall_macros.h) that donor builds pick up
# via -I$(srctree)/drivers/igloobase are carried in the repo instead.
ifeq ($(CONFIG_IGLOO_FAITHFUL),y)
  EXTRA_CFLAGS += -I$(PWD)/faithful-base
endif

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ARCH ?= x86_64
CROSS_COMPILE ?=
EXTRA_CFLAGS += -I$(srctree)/drivers/igloobase \
			 -I$(PWD)/ \
			 -I$(PWD)/portal \
			 -I$(PWD)/hyperfs \
			 -I$(PWD)/hooks

ifeq ($(CONFIG_IGLOO_OSI_MINIMAL),y)

# Faithful OSI-minimal: only the units that link against a bare vendor kernel.
# kl_min_stubs.o supplies FAIL-stubs for the dropped ops (keeping the op ENUM
# whole) plus minimal task-lookup helpers.
igloo-objs := igloo_hc.o \
	portal/portal.o portal/portal_osi.o portal/portal_offsets.o \
	portal/scope.o portal/kl_faithful.o portal/kl_min_stubs.o

else

# Full build. kl_min_stubs.c is minimal-profile-only (its stubs would collide
# with the real handlers); kl_faithful.c is kept (it provides the kl_* helper
# pointers every profile's call sites use, and is inert unless CONFIG_IGLOO_*).
PORTAL_SRCS := $(filter-out $(src)/portal/portal_tramp_gen.c, $(wildcard $(src)/portal/*.c))
PORTAL_SRCS := $(filter-out $(src)/portal/kl_min_stubs.c, $(PORTAL_SRCS))
PORTAL_OBJS := $(patsubst $(src)/%.c,%.o,$(PORTAL_SRCS))

igloo-objs += igloo_hc.o hooks/syscalls_hc.o hooks/ioctl_hc.o \
        hooks/sock_hc.o hooks/uname_hc.o hooks/block_mounts.o \
		hooks/igloo_open.o hooks/signal_hc.o hooks/exit_hc.o \
		hyperfs/hyperfs.o \
		netdevs/igloonet.o \
		$(PORTAL_OBJS)

endif

PORTAL_TRAMP_GEN := $(src)/portal/portal_tramp_gen.h
PORTAL_FFI_GEN := $(src)/portal/ffi_stubs_generated.h

$(PORTAL_TRAMP_GEN): $(src)/../scripts/gen_portal_tramp.py
	python3 $< > $@

$(PORTAL_FFI_GEN): $(src)/../scripts/gen_ffi_stubs.py
	python3 $< $@

ifeq ($(CONFIG_IGLOO_OSI_MINIMAL),y)
# The minimal object set includes neither portal_tramp.c nor portal_ffi.c, so
# the generated headers are not needed -- skip codegen (it also needs python3).
all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CROSS_COMPILE=$(CROSS_COMPILE) modules
else
all: $(PORTAL_TRAMP_GEN) $(PORTAL_FFI_GEN)
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CROSS_COMPILE=$(CROSS_COMPILE) modules
endif

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
