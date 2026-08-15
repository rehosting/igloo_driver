# igloo.ko for one (kernel version, target) cell.
#
# The kernel DERIVATION is the input, not an unpacked kernel-devel tarball.
# That is the entire reason this file exists here rather than as a shell script
# driving a container.
#
# A module is only loadable by the exact kernel build it was compiled against:
# its modversion CRCs come from that kernel's headers and Module.symvers, and
# the kernel's .config itself contains options Kconfig resolves BY PROBING THE
# COMPILER (CONFIG_STACKPROTECTOR_PER_TASK, CONFIG_INIT_STACK_*, the whole
# CC_HAS_* family). So the ABI moves when the toolchain moves, even with
# byte-identical sources and byte-identical config files.
#
# That is not hypothetical. Pairing driver v0.0.96 (built in the
# embedded-toolchains image, gcc 11.2.1 from an unversioned musl.cc download)
# with linux_builder's nix kernels (Buildroot gcc 13.3) put 129 of 221 CRCs out
# of agreement. The only symptom was
#     igloo: disagrees about version of symbol module_layout
# followed by a guest panic, and nothing in either release recorded what it had
# been built against -- so the mismatch was undiscoverable until boot.
#
# Taking the kernel as a build input makes that pair unrepresentable: ARCH,
# CROSS_COMPILE and the compiler all come out of the kernel's passthru, so
# "built against a different kernel" is a different derivation with a different
# store path, not a silent runtime failure.
{ pkgs, kernelsmith }:

{ kernel, src, version, target }:

kernelsmith.buildModule {
  name = "igloo-${version}-${target}";
  inherit version src kernel;

  # src/Makefile is not a bare `obj-m :=` file. Its default target generates two
  # headers (portal_tramp_gen.h, ffi_stubs_generated.h) with python3 and only
  # then re-enters kbuild. Driving kbuild directly would skip the codegen and
  # fail on the missing headers -- see buildModule's `entry` documentation.
  entry = "wrapper";

  nativeBuildInputs = [ pkgs.python3 ];

  # The kbuild Makefile lives in src/; everything it references is relative to
  # it ($(src)/portal, $(src)/../scripts), so the whole repo is the source and
  # src/ is the working directory.
  preBuild = "cd src";

  # NB: nothing here about 32-bit powerpc. arch/powerpc/Makefile appends a BARE
  # RELATIVE `arch/powerpc/lib/crtsavres.o` to KBUILD_LDFLAGS_MODULE, which the
  # linker resolves against the cwd -- the module directory under M=, not the
  # kernel tree. kernelsmith's buildModule stages it, because it is a property
  # of ppc32 kbuild rather than of this module. _in_container_build.sh carries
  # its own copy of that workaround plus an EXTRA_LDFLAGS="-L..." that does
  # nothing at all: the object is named positionally, and -L only affects -l.
}
