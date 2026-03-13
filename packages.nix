{ inputs, ... }: {
  perSystem = { pkgs, self', ... }: {
    packages.default = self'.packages.secrets-tool;
    packages.secrets-tool =
      let craneLib = inputs.crane.mkLib pkgs;
      in craneLib.buildPackage {
        name = "secrets-tool";
        src = craneLib.cleanCargoSource ./.;
        meta.mainProgram = "secrets-tool";

        buildInputs = [ pkgs.openssl ];
        nativeBuildInputs = [ pkgs.pkg-config ];
      };
  };
}
