let
  secretPath = { name, storageDir, label, hostPubkey, file }:
    let
      pubkeyHash = builtins.hashString "sha256" hostPubkey;
      fileHash = builtins.hashFile "sha256" file;
      prefix = builtins.substring 0 32 (builtins.hashString "sha256" (pubkeyHash + fileHash));
      filename = "${prefix}-${name}.age";
    in
    storageDir + "/${label}/${filename}";
in
{ flake-parts-lib, moduleWithSystem, ... }: {
  flake.flakeModules.default = { lib, config, self, ... }:
    let
      inherit (lib) types;

      userFlakeDir = toString self.outPath;

      relativeToFlake = path:
        let rawPath = toString path;
        in if lib.hasPrefix userFlakeDir rawPath
        then lib.removePrefix "/" (lib.removePrefix userFlakeDir rawPath)
        else null;

    in
    {
      options = {
        secrets = {
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

          defaults = {
            hosts = lib.mkOption {
              type = types.listOf types.str;
              default = [ ];
            };
          };

          outputs.nixosModule = lib.mkOption {
            type = types.raw;
          };
        };

        perSystem =
          let topConfig = config;
          in flake-parts-lib.mkPerSystemOption (moduleWithSystem ({ self', ... } @ toplevel: { pkgs, self', config, ... }:
            let
              configFile = pkgs.writers.writeJSON "config.json" {
                hosts = lib.flip lib.mapAttrs topConfig.secrets.hosts (_: v: {
                  storageDir = relativeToFlake v.storageDir;
                  inherit (v) hostPubkey;
                });

                secrets = lib.flip lib.mapAttrs topConfig.secrets.secrets
                  (name: v: {
                    inherit (v) hosts terraform;
                    file = relativeToFlake v.file;
                  } // lib.optionalAttrs (v.generator != null) {
                    generator =
                      let generator = v.generator { inherit pkgs lib; };
                      in {
                        inherit (generator) dependencies;
                        command = lib.getExe (pkgs.writeShellApplication {
                          name = "generate-${name}";
                          text = generator.script;
                          inherit (generator) runtimeEnv runtimeInputs;
                          inheritPath = false;
                          extraShellCheckFlags = [ "--enable=check-extra-masked-returns" ];
                        });
                      };
                  });

                inherit (topConfig.secrets) masterIdentities;
              };
            in
            {
              options.secrets = {
                outputs.mkShell = lib.mkOption {
                  type = types.functionTo types.package;
                  readOnly = true;
                  default = { env, export ? true }:
                    let
                      secrets = lib.mapAttrs (_: v: v.file) topConfig.secrets.secrets;
                      json = pkgs.writers.writeJSON "secrets.json" (env secrets);
                    in
                    pkgs.mkShell {
                      shellHook = ''
                        source <(${lib.getExe config.secrets.outputs.tool} env ${lib.optionalString export "--export"} ${json})
                      '';
                    };
                };
                outputs.tool = lib.mkOption {
                  type = lib.types.package;
                  readOnly = true;
                  default = pkgs.runCommand "secrets"
                    {
                      buildInputs = [ pkgs.makeWrapper ];
                      meta.mainProgram = "secrets";
                      passthru.config = configFile;
                    } ''
                    mkdir -p $out/bin
                    makeWrapper \
                      ${lib.getExe toplevel.self'.packages.secrets-tool} \
                      $out/bin/secrets \
                      --set SECRETS_CONFIG_PATH ${configFile}
                  '';
                };
              };
            }));
      };

      config = {
        secrets.hosts =
          let
            hasColmenaNodes = self ? colmenaHive && self.colmenaHive.nodes != { };
            hasNixosConfigurations = self ? nixosConfigurations && self.nixosConfigurations != { };
            nodes =
              if hasColmenaNodes && !hasNixosConfigurations
              then self.colmenaHive.nodes
              else if !hasColmenaNodes && hasNixosConfigurations
              then self.nixosConfigurations
              else if hasColmenaNodes && hasNixosConfigurations
              then builtins.throw "Both colmena and nixos nodes"
              else { };
          in
          lib.flip lib.mapAttrs nodes (name: h: {
            hostPubkey = h.config.secrets.hostPubkey;
            storageDir = config.secrets.storageDir + "/${name}";
          });

        secrets.outputs.nixosModule =
          let flakeConfig = config; in
          { lib, config, ... }: {
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
                      inherit (flakeConfig.secrets) storageDir;
                      inherit (value) file;
                    };
                  };
                in
                lib.mapAttrs transform (lib.filterAttrs predicate flakeConfig.secrets.secrets);
            };
          };
      };
    };
}
