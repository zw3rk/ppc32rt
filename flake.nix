{
  description = "ppc32rt — 32-bit PowerPC (750 / e500v2) to AArch64 Linux user-mode binary translator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      darwinSystem = "aarch64-darwin";
      darwinPkgs   = nixpkgs.legacyPackages.${darwinSystem};
      linuxSystem = "x86_64-linux";
      linuxPkgs   = nixpkgs.legacyPackages.${linuxSystem};
      aarch64LinuxPkgs = nixpkgs.legacyPackages.aarch64-linux;

      # Cross-compilers for aarch64-unknown-linux-musl (ppc32rt itself)
      darwinA64Musl = darwinPkgs.pkgsCross.aarch64-multiplatform-musl;
      linuxA64Musl  = linuxPkgs.pkgsCross.aarch64-multiplatform-musl;

      mkPpc32rt = crossPkgs: crossPkgs.stdenv.mkDerivation {
        pname = "ppc32rt";
        version = "0.1.0";
        src = ./.;

        dontStrip = true;
        enableParallelBuilding = true;

        buildPhase = ''
          runHook preBuild
          CC="${crossPkgs.stdenv.cc.targetPrefix}gcc"
          command -v "$CC" >/dev/null 2>&1 || CC="${crossPkgs.stdenv.cc.targetPrefix}cc"
          make build CC="$CC"
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/include
          cp _build/ppc32rt $out/bin/ppc32rt
          # argv0 alias for binfmt_misc registration (mirrors a32rt/i686rt).
          ln -sf ppc32rt $out/bin/ppc32rt-binfmt-p
          cp include/a32host.h $out/include/a32host.h
          runHook postInstall
        '';

        meta = with crossPkgs.lib; {
          description = "Standalone static-PIE PPC32 (750 / e500v2) -> AArch64 Linux user-mode translator";
          mainProgram = "ppc32rt";
          platforms = [ "aarch64-linux" ];
          license = licenses.asl20;
        };
      };

      # mkPpc32rtTests — eval-only placeholder, intentionally a plain
      # attrset (nothing to build yet).  Phase 1 lands the real guest
      # fixture suite: PPC32 test binaries must be cross-built with a
      # powerpc musl toolchain — never a glibc-based one.
      mkPpc32rtTests = {
        status = "placeholder — fixtures arrive in Phase 1; never pkgsPowerpc glibc";
      };

    in {
      packages.${darwinSystem} = {
        ppc32rt = mkPpc32rt darwinA64Musl;
        default = self.packages.${darwinSystem}.ppc32rt;
      };

      checks.${darwinSystem} = {
        ppc32rt = self.packages.${darwinSystem}.ppc32rt;
      };

      packages.${linuxSystem} = {
        ppc32rt = mkPpc32rt linuxA64Musl;
        default = self.packages.${linuxSystem}.ppc32rt;
      };

      checks.${linuxSystem} = {
        ppc32rt = self.packages.${linuxSystem}.ppc32rt;
      };

      packages.aarch64-linux = {
        ppc32rt = mkPpc32rt aarch64LinuxPkgs.pkgsMusl;
        default = self.packages.aarch64-linux.ppc32rt;
      };

      checks.aarch64-linux = {
        ppc32rt = self.packages.aarch64-linux.ppc32rt;
      };

      # Exposed for `nix eval .#ppc32rtTests` only (eval-only, see above).
      ppc32rtTests = mkPpc32rtTests;

      # ── Hydra Jobs (ci.zw3rk.com) ───────────────────────────────────
      hydraJobs = {
        ${linuxSystem} = {
          ppc32rt = self.packages.${linuxSystem}.ppc32rt;
        };
        aarch64-linux = {
          ppc32rt = self.packages.aarch64-linux.ppc32rt;
        };
        ${darwinSystem} = {
          ppc32rt = self.packages.${darwinSystem}.ppc32rt;
        };
      };

      devShells.${darwinSystem}.default = darwinPkgs.mkShell {
        name = "ppc32rt-dev";
        buildInputs = [
          darwinPkgs.gnumake
          darwinA64Musl.stdenv.cc
        ];
      };
    };
}
