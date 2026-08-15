# Assert that every module's modversion CRCs agree with its kernel's.
#
# Building against a kernel DERIVATION makes the right INPUTS structural -- it
# is not possible to point this build at last week's kernel. It does not prove
# the OUTPUT is right: kbuild will happily produce a module with no `__versions`
# section at all if CONFIG_MODVERSIONS is off in a config, and nothing else here
# would notice. The symptom of either failure is identical and arrives at insmod
# inside a guest:
#
#     igloo: disagrees about version of symbol module_layout
#
# followed by a panic. That shipped once already -- 129 of 221 CRCs out of
# agreement -- and was undiscoverable until boot. This is the check that would
# have caught it, and it costs a few seconds for the whole matrix.
{ pkgs }:

let
  inherit (pkgs) lib;

  checker = pkgs.writers.writePython3 "modversion-crc-check" { flakeIgnore = [ "E501" ]; } ''
    """Compare a module's __versions CRCs against its kernel's Module.symvers."""
    import struct
    import sys

    ko, symvers, label = sys.argv[1], sys.argv[2], sys.argv[3]

    blob = open(ko, "rb").read()
    if blob[:4] != b"\x7fELF":
        print(f"FAIL {label}: not an ELF file")
        sys.exit(1)

    # The ELF section table is read here rather than shelled out to objcopy.
    # nixpkgs' binutils is built for the host target, so `objcopy
    # --dump-section` fails outright on several of the machines in this matrix
    # -- and it also writes its temp file beside the input, which is in the
    # read-only store. Parsing 40 lines of section header is both portable
    # across every target and free.
    is64 = blob[4] == 2
    endian = "<" if blob[5] == 1 else ">"
    csz = 8 if is64 else 4

    if is64:
        e_shoff, = struct.unpack_from(endian + "Q", blob, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", blob, 0x3A)
        shfmt, off_i, size_i = endian + "IIQQQQ", 4, 5
    else:
        e_shoff, = struct.unpack_from(endian + "I", blob, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", blob, 0x2E)
        shfmt, off_i, size_i = endian + "IIIIII", 4, 5


    def shdr(i):
        return struct.unpack_from(shfmt, blob, e_shoff + i * e_shentsize)


    strtab_off, strtab_size = shdr(e_shstrndx)[off_i], shdr(e_shstrndx)[size_i]
    strtab = blob[strtab_off:strtab_off + strtab_size]

    data = None
    for i in range(e_shnum):
        h = shdr(i)
        name = strtab[h[0]:strtab.index(b"\0", h[0])].decode()
        if name == "__versions":
            data = blob[h[off_i]:h[off_i] + h[size_i]]
            break

    if data is None:
        print(f"FAIL {label}: no __versions section -- CONFIG_MODVERSIONS is off "
              f"for this kernel, so nothing checks the ABI at insmod")
        sys.exit(1)

    # struct modversion_info { unsigned long crc; char name[MODULE_NAME_LEN]; }
    # MODULE_NAME_LEN is (64 - sizeof(Elf_Addr)), so an entry is 64 bytes on
    # every arch -- NOT crc + 56, which silently misparses on 32-bit.
    ent = 64
    if not data or len(data) % ent:
        print(f"FAIL {label}: __versions is {len(data)} bytes, not a multiple of {ent}")
        sys.exit(1)

    mod = {}
    for i in range(0, len(data), ent):
        crc = struct.unpack(endian + ("Q" if csz == 8 else "I"), data[i:i + csz])[0]
        name = data[i + csz:i + ent].split(b"\0")[0].decode()
        if name:
            mod[name] = crc

    kern = {}
    for line in open(symvers):
        f = line.split()
        if len(f) >= 2:
            kern[f[1]] = int(f[0], 16)

    absent = sorted(n for n in mod if n not in kern)
    bad = sorted(n for n in mod if n in kern and kern[n] != mod[n])

    if absent or bad:
        print(f"FAIL {label}: {len(bad)} CRC mismatches, {len(absent)} symbols absent, of {len(mod)}")
        for n in bad[:10]:
            print(f"       {n}: module {mod[n]:#010x} != kernel {kern[n]:#010x}")
        for n in absent[:10]:
            print(f"       absent from kernel: {n}")
        sys.exit(1)

    print(f"ok   {label}: {len(mod)} symbols, all CRCs agree")
  '';

in
{ cells }:

pkgs.runCommand "igloo-driver-modversions-check" { } ''
  fail=0
  ${lib.concatMapStringsSep "\n"
    (c: ''
      symvers=${c.kernel}/Module.symvers
      if [ ! -f "$symvers" ]; then
        echo "FAIL ${c.version}/${c.target}: kernel ships no Module.symvers"
        fail=1
      elif ! ${checker} ${c.module}/igloo.ko "$symvers" "${c.version}/${c.target}"; then
        fail=1
      fi
    '')
    cells}

  if [ $fail -ne 0 ]; then
    echo "modversions check FAILED: a module would be rejected at insmod" >&2
    exit 1
  fi
  echo "modversions check passed" > $out
''
