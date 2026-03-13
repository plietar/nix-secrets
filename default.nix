{ lib, config, self, inputs, ... }:
let
  inherit (lib) types;

  secretPath = { name, storageDir, label, hostPubkey, file }:
    let
      pubkeyHash = builtins.hashString "sha256" hostPubkey;
      fileHash = builtins.hashFile "sha256" file;
      prefix = builtins.substring 0 32 (builtins.hashString "sha256" (pubkeyHash + fileHash));
      filename = "${prefix}-${name}.age";
    in
    storageDir + "/${label}/${filename}";
in
{
  options = {
    secrets = {
      defaults = {
        hosts = lib.mkOption {
          type = types.listOf types.str;
          default = [ ];
        };
      };

      secretsDir = lib.mkOption {
        type = types.nullOr types.path;
        default = null;
      };
      storageDir = lib.mkOption {
        type = types.path;
      };

      secrets = lib.mkOption {
        type = types.attrsOf
          (types.submodule ({ name, ... }: {
            options = {
              file = lib.mkOption {
                type = types.path;
              };
              hosts = lib.mkOption {
                type = types.listOf types.str;
                default = config.secrets.defaults.hosts;
              };
              pure = lib.mkOption {
                type = types.bool;
                default = false;
              };
              terraform = lib.mkOption {
                type = types.nullOr types.str;
                default = null;
              };
              generator = lib.mkOption {
                default = null;
                type =
                  let
                    base = types.submodule {
                      options = {
                        script = lib.mkOption {
                          type = types.str;
                        };
                        dependencies = lib.mkOption {
                          type = types.listOf types.str;
                          default = [ ];
                        };
                        runtimeEnv = lib.mkOption {
                          type = types.attrsOf types.str;
                          default = { };
                        };
                        runtimeInputs = lib.mkOption {
                          type = types.listOf types.package;
                          default = [ ];
                        };
                      };
                    };
                  in
                  types.nullOr (types.coercedTo types.attrs (v: (_: v)) (types.functionTo base));
              };
            };
            config = {
              file = lib.mkIf (config.secrets.secretsDir != null) (lib.mkDefault (config.secrets.secretsDir + "/${name}.age"));
            };
          }));
        default = { };
      };

      masterIdentities = lib.mkOption {
        type = types.listOf types.str;
        default = [ ];
      };

      hosts = lib.mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            hostPubkey = lib.mkOption {
              type = types.str;
            };
            storageDir = lib.mkOption {
              type = types.path;
            };
          };
        });
        default = { };
      };

      specialArgs = lib.mkOption {
        type = types.raw;
        default = {
          _secrets = {
            secrets = config.secrets.secrets;
            storageDir = config.secrets.storageDir;
          };
        };
      };
    };
  };

  config = {
    flake.nixosModules.secrets = { lib, _secrets, config, ... }: {
      options = {
        secrets.hostPubkey = lib.mkOption {
          type = lib.types.str;
        };
        secrets.label = lib.mkOption {
          type = lib.types.str;
          default = config.networking.hostName;
        };
      };

      config = {
        age.secrets =
          let
            predicate = name: value: lib.elem config.secrets.label value.hosts;
            transform = name: value: {
              file = secretPath {
                inherit name;
                inherit (config.secrets) label hostPubkey;
                inherit (_secrets) storageDir;
                inherit (value) file;
              };
            };
          in
          lib.mapAttrs transform (lib.filterAttrs predicate _secrets.secrets);
      };
    };

    perSystem = { pkgs, self', ... }:
      let

      in
      {
        packages.secrets-tool =
          let craneLib = inputs.crane.mkLib pkgs;
          in craneLib.buildPackage {
            name = "secrets-tool";
            src = craneLib.cleanCargoSource ./.;
            meta.mainProgram = "secrets-tool";

            buildInputs = [ pkgs.openssl ];
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

        packages.secrets =
          };

        secrets.hosts = lib.flip lib.mapAttrs self.colmenaHive.nodes (name: h: {
          hostPubkey = h.config.secrets.hostPubkey;
          storageDir = config.secrets.storageDir + "/${name}";
        });
      };
  }
