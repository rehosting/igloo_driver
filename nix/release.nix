# igloo_driver.tar.gz, assembled from per-cell derivations.
#
# Layout is byte-for-byte the one `_in_container_build.sh` produces, because
# penguin's Dockerfile untars this into /igloo_static/ and globs it:
#
#   kernels/BUILT_AGAINST.txt
#   kernels/<version>/igloo.ko.<target>
#   kernels/<version>/igloo.ko.<target>.json.xz
#
# The archive is reproducible (sorted, epoch mtimes, numeric root owner,
# gzip -n), so two builds of the same inputs give the same bytes.
{ pkgs }:

let
  inherit (pkgs) lib;

  reproTar = "--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner";

in
rec {
  # What the modules were built against -- as store paths, not a version string.
  #
  # The Docker path recorded a linux_builder RELEASE TAG here, which is the best
  # a tarball-consuming build can do but is still only a label: two builds from
  # the same tag with a drifting toolchain image produce different ABIs and both
  # claim the same tag. A kernel's store path is a hash of the source, the
  # config, and the compiler, so it names the ABI itself. If a module in this
  # archive refuses to load, the kernel it belongs to is the one named here and
  # nowhere else.
  builtAgainst = { linuxBuilder, cells }:
    pkgs.writeText "BUILT_AGAINST.txt" (''
      Built by igloo_driver's nix path against linux_builder.

      linux_builder: ${linuxBuilder.rev or "(dirty/local)"}
        narHash:     ${linuxBuilder.narHash or "(unknown)"}
        lastModified: ${toString (linuxBuilder.lastModified or 0)}

      Each module below is loadable ONLY on the kernel derivation named beside
      it. A kernel built by a different toolchain rejects it at insmod with
      "disagrees about version of symbol module_layout", because Kconfig
      resolves CONFIG_STACKPROTECTOR_PER_TASK, CONFIG_INIT_STACK_* and the
      CC_HAS_* family by probing the compiler -- so the module ABI moves when
      the compiler moves, even with identical sources and identical configs.

    '' + lib.concatMapStrings
      (c: "  ${c.version}/${c.target}\t${c.kernel}\n")
      (lib.sort (a: b: "${a.version}/${a.target}" < "${b.version}/${b.target}") cells));

  # The archive payload as a plain directory. Exposed on its own so a Nix
  # consumer (penguin) can stage the tree straight into /igloo_static/ instead
  # of packing an archive purely for the consumer to unpack again -- the same
  # seam linux_builder added as `kernels`.
  tree = { linuxBuilder, cells }:
    pkgs.runCommand "igloo-driver-kernels" { } ''
      mkdir -p $out
      cp ${builtAgainst { inherit linuxBuilder cells; }} $out/BUILT_AGAINST.txt
      ${lib.concatMapStringsSep "\n"
        (c: ''
          mkdir -p $out/${c.version}
          cp ${c.ko}  $out/${c.version}/igloo.ko.${c.target}
          cp ${c.isf} $out/${c.version}/igloo.ko.${c.target}.json.xz
        '')
        cells}
    '';

  tarball = { linuxBuilder, cells }:
    pkgs.runCommand "igloo_driver.tar.gz" { nativeBuildInputs = [ pkgs.gzip ]; } ''
      mkdir -p stage
      cp -a ${tree { inherit linuxBuilder cells; }} stage/kernels
      chmod -R u+w stage
      tar ${reproTar} -cf - -C stage kernels | gzip -9n > $out
    '';
}
