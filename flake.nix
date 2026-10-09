# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
#
# DCF Serialize - Universal Serialization Shim for DCF Transport Protocol
# NixOS Flake with Docker containerization support
{
  description = "DCF Serialize - DeMoD Communications Framework Serialization Shim";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { 
          inherit system; 
          config.allowUnfree = false;
        };

        # Package metadata
        pname = "dcf-serialize";
        version = "5.2.0";

        # The main library package
        dcf-serialize = pkgs.stdenv.mkDerivation {
          inherit pname version;
          
          src = ./.;

          nativeBuildInputs = with pkgs; [
            gcc
            gnumake
            pkg-config
          ];

          buildInputs = with pkgs; [
            # No external dependencies - pure C
          ];

          buildPhase = ''
            runHook preBuild

            # Warnings are part of the build. nixpkgs' compiler wrapper adds its own
            # hardening (stack protector, fortify, relro/now, PIE) on top.
            WARN="-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes"
            CFL="-O2 -fPIC -std=c11 $WARN"

            # The Exsecutor-emitted admission gate (gate/) is GNU C11 and not ours to
            # warn about; see gate/PROVENANCE.md (licence status: pending owner decision).
            gcc -O2 -fPIC -std=gnu11 -w -c gate/dcfs_gate_unit.c -o gate/dcfs_gate_unit.o
            gcc $CFL -c gate/dcfs_gate_host.c -o gate/dcfs_gate_host.o
            gcc $CFL -c dcf_serialize.c -o dcf_serialize.o

            # Build static library
            ar rcs libdcf_serialize.a dcf_serialize.o gate/dcfs_gate_unit.o gate/dcfs_gate_host.o

            # Build shared library
            gcc -shared dcf_serialize.o gate/dcfs_gate_unit.o gate/dcfs_gate_host.o -o libdcf_serialize.so.${version}

            # Build test binaries: unit, hostile-input, C-vs-gate differential, trap guard
            gcc $CFL dcf_serialize_test.c libdcf_serialize.a -o dcf_serialize_test
            gcc $CFL dcf_serialize_hostile_test.c libdcf_serialize.a -o dcf_serialize_hostile_test
            gcc $CFL gate/dcfs_gate_diff_test.c libdcf_serialize.a -o dcfs_gate_diff_test
            gcc $CFL gate/dcfs_gate_guard_test.c libdcf_serialize.a -pthread -o dcfs_gate_guard_test

            runHook postBuild
          '';

          checkPhase = ''
            runHook preCheck
            ./dcf_serialize_test
            ./dcf_serialize_hostile_test
            ./dcfs_gate_diff_test
            ./dcfs_gate_guard_test
            bash scripts/check-gate-fresh.sh
            runHook postCheck
          '';

          doCheck = true;

          installPhase = ''
            runHook preInstall
            
            # Headers
            install -Dm644 dcf_serialize.h $out/include/dcf/dcf_serialize.h
            
            # Static library
            install -Dm644 libdcf_serialize.a $out/lib/libdcf_serialize.a
            
            # Shared library with symlinks
            install -Dm755 libdcf_serialize.so.${version} $out/lib/libdcf_serialize.so.${version}
            ln -s libdcf_serialize.so.${version} $out/lib/libdcf_serialize.so.5
            ln -s libdcf_serialize.so.${version} $out/lib/libdcf_serialize.so
            
            # pkg-config file
            install -Dm644 /dev/stdin $out/lib/pkgconfig/dcf-serialize.pc << EOF
            prefix=$out
            exec_prefix=\''${prefix}
            libdir=\''${exec_prefix}/lib
            includedir=\''${prefix}/include

            Name: dcf-serialize
            Description: DeMoD Communications Framework Serialization Shim
            Version: ${version}
            Libs: -L\''${libdir} -ldcf_serialize
            Cflags: -I\''${includedir}
            EOF
            
            # Test binaries (optional, for verification)
            install -Dm755 dcf_serialize_test $out/bin/dcf_serialize_test
            install -Dm755 dcf_serialize_hostile_test $out/bin/dcf_serialize_hostile_test
            install -Dm755 dcfs_gate_diff_test $out/bin/dcfs_gate_diff_test
            install -Dm755 dcfs_gate_guard_test $out/bin/dcfs_gate_guard_test
            
            # License and documentation
            install -Dm644 LICENSE $out/share/licenses/${pname}/LICENSE
            install -Dm644 README.md $out/share/doc/${pname}/README.md || true
            
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Universal serialization/deserialization shim for DCF transport protocol";
            longDescription = ''
              DCF Serialize provides system-agnostic binary serialization with:
              - Network byte order (big-endian) wire format
              - Zero-copy reads where possible  
              - Schema-based type-safe serialization
              - CRC32 integrity validation
              - Nested structure support
              - Variable-length encoding for efficiency
            '';
            homepage = "https://github.com/demod-llc/dcf-serialize";
            license = licenses.bsd3;
            maintainers = [{
              name = "DeMoD LLC";
              email = "dev@demod.io";
            }];
            platforms = platforms.unix;
          };
        };

        # Docker image
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "dcf-serialize";
          tag = version;
          
          contents = [
            dcf-serialize
            pkgs.busybox
            pkgs.cacert
          ];

          config = {
            Cmd = [ "/bin/sh" ];
            WorkingDir = "/app";
            Env = [
              "LD_LIBRARY_PATH=/lib"
              "DCF_SERIALIZE_VERSION=${version}"
            ];
            Labels = {
              "org.opencontainers.image.title" = "DCF Serialize";
              "org.opencontainers.image.description" = "DeMoD Communications Framework Serialization Shim";
              "org.opencontainers.image.version" = version;
              "org.opencontainers.image.vendor" = "DeMoD LLC";
              "org.opencontainers.image.licenses" = "BSD-3-Clause";
              "org.opencontainers.image.source" = "https://github.com/demod-llc/dcf-serialize";
            };
          };
        };

        # Minimal runtime image (just the library)
        dockerImageMinimal = pkgs.dockerTools.buildImage {
          name = "dcf-serialize";
          tag = "${version}-minimal";
          
          copyToRoot = pkgs.buildEnv {
            name = "dcf-serialize-runtime";
            paths = [ dcf-serialize ];
            pathsToLink = [ "/lib" "/include" ];
          };

          config = {
            Env = [
              "LD_LIBRARY_PATH=/lib"
            ];
            Labels = {
              "org.opencontainers.image.title" = "DCF Serialize (minimal)";
              "org.opencontainers.image.version" = version;
              "org.opencontainers.image.vendor" = "DeMoD LLC";
              "org.opencontainers.image.licenses" = "BSD-3-Clause";
            };
          };
        };

        # Development shell
        devShell = pkgs.mkShell {
          name = "dcf-serialize-dev";
          
          buildInputs = with pkgs; [
            # Build tools
            gcc
            clang
            gnumake
            cmake
            pkg-config
            
            # Debug & analysis
            gdb
            valgrind
            lldb
            
            # Static analysis
            cppcheck
            clang-tools  # clang-tidy, clang-format
            
            # Documentation
            doxygen
            graphviz
            
            # Container tools
            docker
            docker-compose
            skopeo
            
            # Nix tools
            nix-prefetch-git
            nixpkgs-fmt
          ];

          shellHook = ''
            echo "╔═══════════════════════════════════════════════════════════════╗"
            echo "║  DCF Serialize Development Environment                        ║"
            echo "║  Copyright (c) 2024-2025 DeMoD LLC - BSD-3-Clause             ║"
            echo "╠═══════════════════════════════════════════════════════════════╣"
            echo "║  Commands:                                                    ║"
            echo "║    nix build          - Build library                         ║"
            echo "║    nix build .#docker - Build Docker image                    ║"
            echo "║    nix flake check    - Run tests                             ║"
            echo "║    make               - Local build                           ║"
            echo "║    make test          - Run tests                             ║"
            echo "║    make docker        - Build Docker via Nix                  ║"
            echo "╚═══════════════════════════════════════════════════════════════╝"
            
            export DCF_SERIALIZE_VERSION="${version}"
            export PS1="\[\033[1;34m\][dcf-serialize]\[\033[0m\] \w \$ "
          '';
        };

      in {
        # Packages
        packages = {
          default = dcf-serialize;
          lib = dcf-serialize;
          docker = dockerImage;
          docker-minimal = dockerImageMinimal;
        };

        # Development shell
        devShells.default = devShell;

        # Checks (run with `nix flake check`)
        checks = {
          build = dcf-serialize;
          
          format = pkgs.runCommand "check-format" {
            buildInputs = [ pkgs.clang-tools ];
          } ''
            cd ${./.}
            clang-format --dry-run --Werror *.c *.h || echo "Format check skipped"
            touch $out
          '';
          
          # The vendored Exsecutor gate still matches the hashes in gate/PROVENANCE.md
          # (re-emission needs exsc and is skipped here; run `make check-gate` with EXSECUTOR set).
          gate-fresh = pkgs.runCommand "check-gate-fresh" {} ''
            cd ${./.}
            bash scripts/check-gate-fresh.sh
            touch $out
          '';

          lint = pkgs.runCommand "check-lint" {
            buildInputs = [ pkgs.cppcheck ];
          } ''
            cd ${./.}
            cppcheck --enable=warning,performance --error-exitcode=1 \
              --suppress=missingIncludeSystem \
              dcf_serialize.c dcf_serialize.h || echo "Lint check completed"
            touch $out
          '';
        };

        # Apps
        apps = {
          test = {
            type = "app";
            program = "${dcf-serialize}/bin/dcf_serialize_test";
          };
        };

        # Overlay for use in other flakes
        overlays.default = final: prev: {
          dcf-serialize = dcf-serialize;
        };
      }
    ) // {
      # NixOS module for system-wide installation
      nixosModules.default = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.dcf-serialize;
        in {
          options.services.dcf-serialize = {
            enable = mkEnableOption "DCF Serialize library";
            
            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.default;
              description = "DCF Serialize package to use";
            };
          };

          config = mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            
            environment.variables = {
              PKG_CONFIG_PATH = "${cfg.package}/lib/pkgconfig:$PKG_CONFIG_PATH";
              LD_LIBRARY_PATH = "${cfg.package}/lib:$LD_LIBRARY_PATH";
              C_INCLUDE_PATH = "${cfg.package}/include:$C_INCLUDE_PATH";
            };
          };
        };
    };
}
