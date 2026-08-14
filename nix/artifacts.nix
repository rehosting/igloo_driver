# The two per-cell artifacts a release ships, derived from one module build.
#
# ORDER MATTERS, and it is the reason these are two derivations rather than one
# script: the ISF has to be extracted from the UNSTRIPPED module, and the
# shipped .ko is stripped. `_in_container_build.sh` gets that right only by
# statement order inside a single function -- run dwarf2json first, strip
# afterwards -- which is exactly the kind of ordering constraint that rots the
# first time someone reorders the file. Here `isf` and `stripped` both take the
# unstripped module as input, so neither can observe the other.
{ pkgs, dwarf2json }:

rec {
  # Volatility-style symbol table for igloo.ko, consumed by penguin at runtime
  # (pyplugins/apis/kffi.py reads the kernel's cosi.<arch>.json.xz; the module's
  # is the same shape for the module's own types).
  #
  # `dwarf2json` here is the REHOSTING FORK, threaded in from linux_builder's
  # flake rather than re-pinned. nixpkgs ships upstream volatilityfoundation's
  # tool under the same name and it produces different output; the Docker image
  # got the fork by `git clone --depth 1` of its default branch, i.e. whatever
  # it said that day. Sharing linux_builder's pin means the kernel ISFs and the
  # module ISFs in a release are produced by one identical tool, which was
  # previously true only by coincidence.
  isf = { module, version, target }:
    pkgs.runCommand "igloo-isf-${version}-${target}"
      {
        nativeBuildInputs = [ dwarf2json pkgs.xz pkgs.binutils ];
        meta.description = "COSI symbol table for igloo.ko ${version}/${target}";
      } ''
      ko=${module}/igloo.ko

      # A module built with debug info stripped would yield a technically valid
      # but empty ISF, so check rather than trust. The kbuild EXTRA_CFLAGS in
      # src/Makefile carry -g; if that is ever dropped this fails here instead
      # of shipping a symbol table with no symbols in it.
      #
      # Assigned to a variable rather than piped straight into grep, so a
      # missing or broken readelf aborts the build (set -e) instead of feeding
      # grep an empty string and being reported as "no debug info" -- which is
      # exactly what an earlier version of this check did.
      sections=$(readelf -S "$ko")
      if ! printf '%s\n' "$sections" | grep -q '\.debug_info'; then
        echo "no .debug_info in $ko -- cannot produce an ISF" >&2
        exit 1
      fi

      dwarf2json linux --elf "$ko" | xz -c > $out
      test -s $out || { echo "dwarf2json produced an empty ISF for $ko" >&2; exit 1; }
    '';

  # The shipped module: debug info removed, using the SAME cross binutils that
  # built it (kernel.passthru.toolchain), not the host's.
  #
  # `--strip-unneeded` matches what `./build.sh --release` does today. It is a
  # heavier hammer than kbuild's own INSTALL_MOD_STRIP default (`--strip-debug`),
  # but it is what every shipped igloo_driver release has been built with, and
  # changing the shipped artifact is not this change's job.
  stripped = { module, kernel, version, target }:
    pkgs.runCommand "igloo-ko-${version}-${target}"
      {
        nativeBuildInputs = [ kernel.passthru.toolchain ];
        meta.description = "igloo.ko ${version}/${target} (stripped)";
      } ''
      cp ${module}/igloo.ko $out
      chmod +w $out
      ${kernel.passthru.crossPrefix}strip --strip-unneeded $out
    '';
}
