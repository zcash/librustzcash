{
  description = "Development environment for the librustzcash workspace";

  # Native Windows is not a supported Nix platform, so the Windows CI builds are not
  # reproduced by these development shells.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      rustTargets = [
        "wasm32-wasip1"
        "thumbv7em-none-eabihf"
      ];
      rustToolchainFor =
        pkgs: channel:
        let
          pinned = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain;
          components =
            pinned.components
            ++ lib.optionals (channel == null || channel == "stable") [
              "rust-src"
              "rust-analyzer"
            ];
        in
        pkgs.rust-bin.fromRustupToolchain {
          channel = if channel == null then pinned.channel else channel;
          inherit components;
          targets = rustTargets;
        };
      mkDevShell =
        pkgs: rustToolchain:
        pkgs.mkShell (
          {
            packages = [
              rustToolchain
              pkgs.cargo-deny
              pkgs.cargo-vet
              pkgs.pkg-config
              pkgs.protobuf
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              # Native toolchains used by the wasm32-wasip1 and
              # thumbv7em-none-eabihf CI builds.
              pkgs.gcc_multi
              pkgs.gcc-arm-embedded
            ];

            PROTOC = "${pkgs.protobuf}/bin/protoc";
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          }
          // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            CC_thumbv7em_none_eabihf = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
            CARGO_TARGET_THUMBV7EM_NONE_EABIHF_LINKER = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
          }
        );
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = mkDevShell pkgs (rustToolchainFor pkgs null);
          stable = mkDevShell pkgs (rustToolchainFor pkgs "stable");
          beta = mkDevShell pkgs (rustToolchainFor pkgs "beta");
          nightly = mkDevShell pkgs (rustToolchainFor pkgs "nightly");
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor pkgs null;
        in
        {
          devShell = self.devShells.${system}.default;
          stable = self.devShells.${system}.stable;
          beta = self.devShells.${system}.beta;
          nightly = self.devShells.${system}.nightly;

          rust-targets =
            pkgs.runCommand "rust-targets-check"
              {
                nativeBuildInputs = [ rustToolchain ];
              }
              ''
                printf '#![no_std]\n' > lib.rs
                for target in ${lib.escapeShellArgs rustTargets}; do
                  rustc --crate-type lib --emit metadata --target "$target" lib.rs
                done
                touch $out
              '';
        }
      );
    };
}
