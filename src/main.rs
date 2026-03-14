mod generate;

use crate::generate::generate_secrets;
use age::armor::{ArmoredReader, ArmoredWriter};
use age::Callbacks;
use anyhow::Context as _;
use camino::Utf8PathBuf;
use clap::{Args, Parser};
use clap_stdin::FileOrStdin;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

#[derive(Args)]
struct RootArg {
    #[arg(long = "root", env = "FLAKE_ROOT")]
    flake_root: Option<PathBuf>,
}

#[derive(Args)]
struct ConfigArg {
    #[arg(long, env = "SECRETS_CONFIG_PATH")]
    config: PathBuf,
}

#[derive(Args)]
struct IdentitesArg {
    #[arg(short, long)]
    identity: Option<PathBuf>,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
enum Command {
    Locate {
        #[command(flatten)]
        root: RootArg,
    },
    Rekey {
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
        #[command(flatten)]
        identities: IdentitesArg,
        #[arg(short, long)]
        force: bool,
        #[arg(long)]
        verbose: bool,
        #[arg(short, long)]
        add_to_git: bool,
    },
    View {
        path: Option<PathBuf>,
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
        #[command(flatten)]
        identities: IdentitesArg,
    },
    Edit {
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
        #[command(flatten)]
        identities: IdentitesArg,
        #[arg(long)]
        input: Option<FileOrStdin>,
        path: Option<PathBuf>,
    },
    UpdateMasterKeys {
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
        #[command(flatten)]
        identities: IdentitesArg,
        path: Option<PathBuf>,
    },
    Generate {
        #[command(flatten)]
        identities: IdentitesArg,
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Env {
        #[command(flatten)]
        identities: IdentitesArg,
        path: PathBuf,
        #[arg(long)]
        export: bool,
    },
    TerraformImport {
        #[command(flatten)]
        identities: IdentitesArg,
        #[command(flatten)]
        config: ConfigArg,
        #[command(flatten)]
        root: RootArg,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Generator {
    dependencies: Vec<String>,
    command: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Secret {
    #[serde(rename = "file")]
    path: Utf8PathBuf,
    hosts: Vec<String>,
    generator: Option<Generator>,
    terraform: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    #[serde(rename = "hostPubkey")]
    pubkey: String,

    storage_dir: Utf8PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    hosts: HashMap<String, Host>,
    master_identities: Vec<String>,
    secrets: HashMap<String, Secret>,
}

impl Config {
    fn master_identities(&self) -> anyhow::Result<Vec<age::ssh::Recipient>> {
        Ok(self
            .master_identities
            .iter()
            .map(|key| age::ssh::Recipient::from_str(&key))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("{:?}", e))?)
    }
}

struct CachedIdentity {
    identity: RefCell<age::ssh::Identity>,
    path: PathBuf,
}
impl CachedIdentity {
    pub fn new(identity: age::ssh::Identity, path: PathBuf) -> CachedIdentity {
        CachedIdentity {
            identity: RefCell::new(identity),
            path,
        }
    }

    pub fn from_file(path: impl Into<PathBuf>) -> std::io::Result<CachedIdentity> {
        let path = path.into();
        let reader = BufReader::new(File::open(&path)?);
        let identity = age::ssh::Identity::from_buffer(reader, None)?;
        Ok(CachedIdentity::new(identity, path))
    }
}

impl age::Identity for CachedIdentity {
    fn unwrap_stanza(
        &self,
        stanza: &age_core::format::Stanza,
    ) -> Option<Result<age_core::format::FileKey, age::DecryptError>> {
        let callbacks = age::cli_common::UiCallbacks;
        let mut inner = self.identity.borrow_mut();
        match *inner {
            age::ssh::Identity::Unencrypted(_) => inner.unwrap_stanza(stanza),
            age::ssh::Identity::Encrypted(ref key) => {
                let prompt = format!("Type passphrase for OpenSSH key '{}'", self.path.display());
                let passphrase = callbacks.request_passphrase(&prompt)?;
                let decrypted = match key.decrypt(passphrase) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                *inner = age::ssh::Identity::Unencrypted(decrypted);
                inner.unwrap_stanza(stanza)
            }
            age::ssh::Identity::Unsupported(_) => None,
        }
    }
}

impl IdentitesArg {
    fn load(&self) -> anyhow::Result<Vec<CachedIdentity>> {
        if let Some(ref path) = self.identity {
            let identity = CachedIdentity::from_file(&path)?;
            Ok(vec![identity])
        } else if let Some(home) = std::env::home_dir() {
            let candidates = [home.join(".ssh/id_rsa"), home.join(".ssh/id_ed25519")];
            let result = candidates
                .into_iter()
                .map(|path| CachedIdentity::from_file(&path))
                .filter_map(|x| {
                    x.map_or_else(
                        |err| {
                            if err.kind() == std::io::ErrorKind::NotFound {
                                Ok(None)
                            } else {
                                Err(err)
                            }
                        },
                        |v| Ok(Some(v)),
                    )
                    .transpose()
                })
                .collect::<Result<_, _>>()?;
            Ok(result)
        } else {
            panic!();
        }
    }
}

impl RootArg {
    fn resolve(&self) -> anyhow::Result<PathBuf> {
        if let Some(ref path) = self.flake_root {
            return Ok(path.to_owned());
        }

        let pwd = std::env::current_dir()?;
        let mut current: Option<&Path> = Some(pwd.as_ref());

        while let Some(this) = current {
            if this.join("flake.nix").exists() {
                return Ok(this.to_owned());
            }

            current = this.parent();
        }

        anyhow::bail!("Could not locate flake root");
    }
}

impl ConfigArg {
    fn load(&self) -> Config {
        serde_json::from_reader(std::fs::File::open(&self.config).unwrap()).unwrap()
    }
}

struct Context {
    config: Config,
    root: PathBuf,
    identities: Vec<CachedIdentity>,
}

fn encrypt<'a>(
    recipients: impl IntoIterator<Item = &'a dyn age::Recipient>,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())?;
    let armored = ArmoredWriter::wrap_output(Vec::new(), age::armor::Format::AsciiArmor)?;
    let mut output = encryptor.wrap_output(armored)?;
    output.write(&data)?;
    let ciphertext = output.finish()?.finish()?;
    Ok(ciphertext)
}

impl Context {
    fn decrypt(&self, path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
        decrypt(path, &self.identities)
    }

    fn encrypt_master(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let identities = self.config.master_identities()?;
        let recipients = identities.iter().map(|x| -> &dyn age::Recipient { x });
        encrypt(recipients, data)
    }

    fn select_secret(&self) -> Option<PathBuf> {
        let options = skim::SkimOptions::default();
        let (tx, rx): (skim::SkimItemSender, skim::SkimItemReceiver) = skim::prelude::unbounded();

        for s in self.config.secrets.values() {
            tx.send(skim::prelude::Arc::new(s.path.clone())).unwrap();
        }

        drop(tx);

        let result = skim::Skim::run_with(&options, Some(rx))
            .map(|out| out.selected_items)
            .unwrap_or_default();

        result
            .first()
            .map(|item| self.root.join(AsRef::<str>::as_ref(&item.output())))
    }
}

fn hash_string(s: &str) -> String {
    let hash = Sha256::digest(s.as_bytes());
    base16ct::lower::encode_string(&hash)
}

fn hash_file(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let path = path.as_ref();
    let mut file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();

    Ok(base16ct::lower::encode_string(&hash))
}

fn decrypt(path: impl AsRef<Path>, identities: &[impl age::Identity]) -> anyhow::Result<Vec<u8>> {
    let reader = BufReader::new(File::open(path)?);
    let armored = ArmoredReader::new(reader);
    let decryptor = age::Decryptor::new(armored)?;

    let identities = identities.iter().map(|x| -> &dyn age::Identity { x });
    let mut stream = decryptor.decrypt(identities)?;
    let mut result = vec![];
    stream.read_to_end(&mut result)?;
    Ok(result)
}

fn remove_stale_secrets(path: impl AsRef<Path>, keep: &HashSet<PathBuf>) {
    let walk = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file());

    for entry in walk {
        let entry = entry.path();
        if !keep.contains(entry) {
            match std::fs::remove_file(entry) {
                Ok(()) => println!("Removed stale secret {}", entry.display()),
                Err(err) => println!(
                    "Could not remove stale secret {}, ignoring: {}",
                    entry.display(),
                    err
                ),
            }
        }
    }
}

fn rekey_secret(
    ctx: &Context,
    source: &Path,
    target: &Path,
    recipient: &dyn age::Recipient,
    repo: Option<&git2::Repository>,
    verbose: bool,
) -> anyhow::Result<()> {
    let plaintext = ctx.decrypt(source)?;
    let ciphertext = encrypt([recipient], &plaintext)?;
    std::fs::write(target, ciphertext)?;

    if let Some(repo) = repo {
        let mut index = repo.index()?;
        let relative = &target.strip_prefix(&ctx.root).unwrap();
        if verbose {
            println!("Adding {} to git", relative.display());
        }
        index.add_path(relative)?;
        index.write()?;
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct TerraformOutput {
    value: String,
}

fn main() -> anyhow::Result<()> {
    match Command::parse() {
        Command::Locate { root } => {
            println!("{}", root.resolve()?.display());
        }

        Command::View {
            config,
            root,
            identities,
            path,
        } => {
            let root = root.resolve()?;
            let identities = identities.load()?;
            let config = config.load();
            let ctx = Context {
                config,
                root,
                identities,
            };

            let Some(path) = path.or_else(|| ctx.select_secret()) else {
                return Ok(());
            };

            let data = ctx.decrypt(path)?;
            std::io::stdout().write_all(&data)?;
        }

        Command::Edit {
            config,
            root,
            identities,
            path,
            input,
        } => {
            let root = root.resolve()?;
            let config = config.load();
            let identities = identities.load()?;
            let ctx = Context {
                config,
                root,
                identities,
            };

            let Some(path) = path.or_else(|| ctx.select_secret()) else {
                return Ok(());
            };

            if let Some(input) = input {
                let mut reader = input.into_reader()?;
                let mut plaintext = vec![];
                reader.read_to_end(&mut plaintext)?;
                let ciphertext = ctx.encrypt_master(&plaintext)?;
                std::fs::write(&path, ciphertext)?;
                println!("Secret was written");
            } else {
                let exists = path.exists();
                let plaintext = if exists {
                    ctx.decrypt(&path)?
                } else {
                    Vec::new()
                };
                let updated = edit::edit_bytes(&plaintext)?;
                if !exists || plaintext != updated {
                    let ciphertext = ctx.encrypt_master(&updated)?;
                    std::fs::write(&path, ciphertext)?;
                }
                if !exists {
                    println!("{} was created", path.display());
                } else if plaintext == updated {
                    println!("{} was not changed", path.display());
                } else {
                    println!("{} was updated", path.display());
                }
            }
        }

        Command::Rekey {
            config,
            root,
            identities,
            force,
            add_to_git,
            verbose,
        } => {
            let root = root.resolve()?;
            let config = config.load();
            let identities = identities.load()?;
            let ctx = Context {
                config,
                root,
                identities,
            };

            let repository = add_to_git
                .then(|| git2::Repository::open(&ctx.root))
                .transpose()?;

            let mut tracked_secrets = HashSet::new();
            for secret in ctx.config.secrets.values() {
                let source = ctx.root.join(&secret.path);
                let source_hash = hash_file(&source)?;
                for hostname in &secret.hosts {
                    let host = &ctx.config.hosts[hostname];
                    // TODO: cache these
                    let storage_dir = ctx.root.join(&host.storage_dir);
                    let pubkey_hash = hash_string(&host.pubkey);

                    let recipient = age::ssh::Recipient::from_str(&host.pubkey).unwrap();

                    let target_hash = hash_string(&format!("{}{}", pubkey_hash, source_hash));
                    let target = storage_dir.join(format!(
                        "{}-{}.age",
                        &target_hash[..32],
                        secret.path.file_stem().unwrap(),
                    ));
                    tracked_secrets.insert(target.clone());

                    if !target.exists() || force {
                        println!(
                            "Rekeying {} for {}",
                            secret.path.file_name().unwrap(),
                            hostname
                        );
                        rekey_secret(
                            &ctx,
                            &source,
                            &target,
                            &recipient,
                            repository.as_ref(),
                            verbose,
                        )?;
                    } else if verbose {
                        println!(
                            "Skipping {} for {}",
                            secret.path.file_name().unwrap(),
                            hostname
                        );
                    }
                }
            }

            for host in ctx.config.hosts.values() {
                let storage_dir = ctx.root.join(&host.storage_dir);
                remove_stale_secrets(storage_dir, &tracked_secrets);
            }
        }

        Command::UpdateMasterKeys {
            config,
            root,
            path,
            identities,
        } => {
            let root = root.resolve()?;
            let config = config.load();
            let identities = identities.load()?;
            let ctx = Context {
                config,
                root,
                identities,
            };

            let paths = path.map(|p| vec![p]).unwrap_or_else(|| {
                ctx.config
                    .secrets
                    .values()
                    .map(|s| ctx.root.join(&s.path).into())
                    .collect()
            });

            for path in paths {
                println!("Encrypting {}", path.display());
                let plaintext = ctx.decrypt(&path)?;
                let ciphertext = ctx.encrypt_master(&plaintext)?;
                std::fs::write(path, ciphertext)?;
            }
        }
        Command::Generate {
            config,
            root,
            force,
            dry_run,
            identities,
        } => {
            let root = root.resolve()?;
            let config = config.load();
            let identities = identities.load()?;
            let ctx = Context {
                config,
                root,
                identities,
            };

            generate_secrets(&ctx, force, dry_run)?;
        }
        Command::Env {
            path,
            export,
            identities,
        } => {
            let file = std::fs::File::open(path)?;
            let secrets: HashMap<String, Utf8PathBuf> = serde_json::from_reader(file)?;
            let identities = identities.load()?;

            for (name, path) in secrets {
                let plaintext = decrypt(&path, &identities).unwrap();
                let plaintext = String::from_utf8(plaintext).unwrap();
                let plaintext = plaintext.trim_end_matches("\n");
                let plaintext = shlex::try_quote(plaintext).unwrap();
                if export {
                    println!("export {name}={plaintext}");
                } else {
                    println!("{name}={plaintext}");
                }
            }
        }
        Command::TerraformImport {
            config,
            root,
            identities,
        } => {
            let root = root.resolve()?;
            let config = config.load();
            let identities = identities.load()?;
            let ctx = Context {
                config,
                root,
                identities,
            };

            let values: HashMap<String, TerraformOutput> =
                serde_json::from_reader(std::io::stdin().lock())?;

            for (_, secret) in &ctx.config.secrets {
                if let Some(ref name) = secret.terraform {
                    let path = ctx.root.join(&secret.path);
                    let output = values.get(name).unwrap();
                    let plaintext = format!("{}\n", output.value).into_bytes();
                    if !path.exists() || ctx.decrypt(&path)? != plaintext {
                        let ciphertext = ctx.encrypt_master(&plaintext)?;
                        std::fs::write(&path, ciphertext)?;
                        println!("Imported {}", secret.path);
                    } else {
                        println!("{} was unchanged", secret.path);
                    }
                }
            }
        }
    }

    Ok(())
}
