{
  description = "Oblivious Gateway dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system}.extend (import rust-overlay);
        in {
          default = pkgs.mkShell {
            packages = [
              (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
              pkgs.cmake
              pkgs.clang
              pkgs.pkg-config
            ];
          };
        });
    };
}
