# faithful-base — base API headers for faithful (out-of-tree) builds

On penguin's donor kernels, igloo is built in-tree and picks up its base API
headers from `drivers/igloobase` (via `-I$(srctree)/drivers/igloobase` in the
Makefile). A Tier-A faithful build loads `igloo.ko` into an *unmodified vendor
kernel* whose tree has no `drivers/igloobase`, so these arch-neutral API headers
are carried here and added to the include path whenever `CONFIG_IGLOO_FAITHFUL`
is set (see `../Makefile`).

Keep these in sync with the canonical `drivers/igloobase` copies. `igloo.h` here
is byte-identical to `local_packages/kdevel/*/include/igloo.h`.
