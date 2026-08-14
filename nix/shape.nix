# Assert that each module is actually the machine its target name claims.
#
# This is the check the Docker build never had, and the failure class is real:
# `_in_container_build.sh` collapses every powerpc* target onto ARCH=powerpc and
# picks the cross prefix by string matching, so a cell can compile cleanly and
# produce an object for the wrong machine while `igloo.ko` exists and the log
# says SUCCESS. linux_builder shipped two bugs of exactly this shape before
# adding the equivalent check (four byte-identical big-endian perf binaries, and
# a "powerpcle" kernel that was big-endian) -- both invisible to every check
# that only asked whether the artifact existed.
#
# A .ko is a relocatable ELF, so unlike a compressed kernel image its class,
# byte order and machine are all readable directly. Every cell is covered; there
# is no partial-coverage escape hatch.
#
# Deliberately derived from the TARGET NAME, not from the toolchain or the
# kernel config -- those are the things being checked. The name is what every
# consumer downstream believes.
{ pkgs }:

let
  inherit (pkgs) lib;

  # target -> what `file` must say. `machine` is matched as a substring, so it
  # tolerates the trailing detail `file` adds (ARM EABI version, MIPS ABI/ISA).
  expect = {
    armel = { bits = 32; endian = "LSB"; machine = "ARM"; };
    arm64 = { bits = 64; endian = "LSB"; machine = "ARM aarch64"; };
    mipsel = { bits = 32; endian = "LSB"; machine = "MIPS"; };
    mipseb = { bits = 32; endian = "MSB"; machine = "MIPS"; };
    mips64el = { bits = 64; endian = "LSB"; machine = "MIPS"; };
    mips64eb = { bits = 64; endian = "MSB"; machine = "MIPS"; };
    powerpc = { bits = 32; endian = "MSB"; machine = "PowerPC"; };
    powerpc64 = { bits = 64; endian = "MSB"; machine = "64-bit PowerPC"; };
    powerpc64le = { bits = 64; endian = "LSB"; machine = "64-bit PowerPC"; };
    loongarch64 = { bits = 64; endian = "LSB"; machine = "LoongArch"; };
    riscv64 = { bits = 64; endian = "LSB"; machine = "UCB RISC-V"; };
    x86_64 = { bits = 64; endian = "LSB"; machine = "x86-64"; };
  };

in
{ cells }:

pkgs.runCommand "igloo-driver-shape-check"
{
  nativeBuildInputs = [ pkgs.file ];
} ''
  fail=0
  report() { printf '%-22s %-9s %s\n' "$1" "$2" "$3"; }

  ${lib.concatMapStringsSep "\n"
    (c:
      let e = expect.${c.target} or null; in
      if e == null then ''
        # An unrecognised target name FAILS rather than passing quietly. A new
        # arch must declare what it is here; silently skipping it is how the
        # partial coverage this check exists to prevent creeps back in.
        report "${c.version}/${c.target}" "UNKNOWN" "no expectation declared in nix/shape.nix"
        fail=1
      '' else ''
        ko=${c.module}/igloo.ko
        [ -f "$ko" ] || { report "${c.version}/${c.target}" "MISSING" "$ko"; fail=1; }
        if [ -f "$ko" ]; then
          desc=$(file -b "$ko")
          ok=1
          case "$desc" in *"${toString e.bits}-bit ${e.endian}"*) ;; *) ok=0 ;; esac
          case "$desc" in *"${e.machine}"*) ;; *) ok=0 ;; esac
          # It must also still be a MODULE. A .ko that came out as an executable
          # or a shared object is not loadable, and the name would not say so.
          case "$desc" in *relocatable*) ;; *) ok=0 ;; esac
          if [ "$ok" = 1 ]; then
            report "${c.version}/${c.target}" "ok" "$desc"
          else
            report "${c.version}/${c.target}" "MISMATCH" \
              "want ${toString e.bits}-bit ${e.endian} ${e.machine} relocatable, got: $desc"
            fail=1
          fi
        fi
      '')
    cells}

  if [ $fail -ne 0 ]; then
    echo "shape check FAILED: a module's ELF class/byte order/machine disagrees with its target name" >&2
    exit 1
  fi
  echo "shape check passed" > $out
''
