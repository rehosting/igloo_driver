{
  description = "igloo.ko: the IGLOO out-of-tree kernel module, cross-built against linux_builder's kernels";

  nixConfig = {
    extra-substituters = [ "https://rehosting-tools.cachix.org" ];
    extra-trusted-public-keys = [
      "rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    ];
  };

  inputs = {
    # The kernels, as DERIVATIONS -- not as a kernel-devel tarball.
    #
    # This is the whole change. The Docker path downloads
    # kernel-devel-all.tar.gz from a linux_builder release, unpacks it to a
    # scratch directory and builds against whatever is there. Two things are
    # wrong with that, and only one of them is obvious:
    #
    #  1. Nothing ties the unpacked tree to the kernel the module will be
    #     inserted into. The pin was a release TAG, which is a label rather
    #     than an identity: rebuild that tag with a drifted toolchain image and
    #     you get a different ABI under the same name.
    #
    #  2. A nix-built kernel-devel tree is not consumable from a non-nix
    #     container AT ALL. It ships prebuilt host tools, and those are linked
    #     against the Nix store -- `scripts/basic/fixdep` requests interpreter
    #     /nix/store/...-glibc-2.39-52/lib/ld-linux-x86-64.so.2. Inside
    #     embedded-toolchains (Ubuntu, no /nix/store) every target died within
    #     seconds of `make` starting. That is not a bug to fix in the tarball;
    #     it is what "prebuilt host tools" means.
    #
    # Taking the flake makes the kernel derivation the input, so ARCH,
    # CROSS_COMPILE and the compiler all come from the kernel itself and a
    # mismatched (kernel, module) pair stops being representable.
    linux-builder.url = "github:rehosting/linux_builder/nixdev_0.1.0";

    # Follow, do not re-pin. buildModule reads the toolchain out of the
    # kernel's passthru, so the compiler is already whatever built the kernel;
    # following just avoids evaluating a second kernelsmith and a second
    # nixpkgs to reach the same store paths.
    kernelsmith.follows = "linux-builder/kernelsmith";
    nixpkgs.follows = "linux-builder/nixpkgs";
  };

  outputs =
    { self, nixpkgs, kernelsmith, linux-builder }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;

      lbPkgs = linux-builder.packages.${system};

      # The matrix is DERIVED from linux_builder, not restated here.
      #
      # build.sh carries its own TARGETS and VERSIONS lists, which have to be
      # kept in step with linux_builder's configs/ by hand; when they drift the
      # symptom is a silent "SKIPPED (No kernel config)" line in a log nobody
      # reads. Reading the kernel cells out of the flake means this repo builds
      # for exactly the kernels that exist, always.
      #
      # The version component must start with a digit so `kernel-devel-all`
      # is not mistaken for a cell named devel/all.
      parse = name:
        let m = builtins.match "kernel-([0-9][^-]*)-(.+)" name; in
        if m == null then null else {
          version = builtins.elemAt m 0;
          target = builtins.elemAt m 1;
          kernel = lbPkgs.${name};
        };

      kernelCells = builtins.filter (c: c != null)
        (map parse (builtins.attrNames lbPkgs));

      # An empty matrix would make `nix build .#all` and the release tarball
      # succeed while shipping nothing at all -- the exact failure this repo
      # has had before, just moved. Fail at evaluation instead.
      _ = lib.assertMsg (kernelCells != [ ])
        "no kernel-<version>-<target> outputs found in linux_builder; the naming convention changed";

      mkModule = import ./nix/module.nix { inherit pkgs kernelsmith; };
      artifacts = import ./nix/artifacts.nix {
        inherit pkgs;
        # The rehosting FORK of dwarf2json, pinned once in linux_builder and
        # reused here rather than re-derived. See nix/artifacts.nix.
        inherit (lbPkgs) dwarf2json;
      };
      releaseLib = import ./nix/release.nix { inherit pkgs; };

      # Per cell: the unstripped module, the ISF taken from it, and the
      # stripped copy that ships.
      cells = map
        (c:
          let
            module = mkModule {
              inherit (c) kernel version target;
              src = self;
            };
          in
          c // {
            inherit module;
            isf = artifacts.isf { inherit module; inherit (c) version target; };
            ko = artifacts.stripped { inherit module; inherit (c) kernel version target; };
          })
        kernelCells;

      cellName = c: "${c.version}-${c.target}";

      # Individually addressable, so a single broken arch can be reached
      # without rebuilding the whole matrix to see one compiler error.
      perCell = lib.listToAttrs (lib.concatMap
        (c: [
          (lib.nameValuePair "igloo-${cellName c}" c.module)
          (lib.nameValuePair "isf-${cellName c}" c.isf)
          (lib.nameValuePair "ko-${cellName c}" c.ko)
        ])
        cells);

    in
    {
      packages.${system} = perCell // {
        default = perCell."igloo-6.13-armel";

        # Every module, in one derivation, for CI.
        all = pkgs.linkFarm "igloo-driver-all"
          (map (c: { name = cellName c; path = c.module; }) cells);

        # The release artifact, drop-in for the Docker build's.
        igloo_driver = releaseLib.tarball {
          linuxBuilder = linux-builder;
          inherit cells;
        };

        # The same payload as a directory, for Nix consumers that would
        # otherwise tar it here and untar it there.
        kernels = releaseLib.tree {
          linuxBuilder = linux-builder;
          inherit cells;
        };

        # Every module's ELF class, byte order and machine must match what its
        # target name claims. Cheap, and the only check that catches a cell
        # which compiles cleanly and produces the wrong machine's object --
        # linux_builder shipped two such bugs before adding the equivalent.
        shape-check = import ./nix/shape.nix { inherit pkgs; } { inherit cells; };
      };

      # The (version, target) pairs this flake builds for, as data. Useful for
      # CI to enumerate without hardcoding a matrix.
      matrix.${system} = map (c: { inherit (c) version target; }) kernelCells;

      checks.${system} = {
        inherit (self.packages.${system}) shape-check;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ gnumake python3 bc ];
        shellHook = ''
          echo "igloo_driver (nix)"
          # NB: cell names contain a '.', which nix parses as an attrpath
          # separator -- quote the attribute or it fails to resolve.
          echo '  nix build .#packages.x86_64-linux."igloo-6.13-armel"   one module'
          echo "  nix build .#all                                       every module"
          echo "  nix build .#igloo_driver                              the release tarball"
          echo "  nix flake check                                       shapes match target names"
        '';
      };
    };
}
