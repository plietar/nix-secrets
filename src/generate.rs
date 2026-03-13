use crate::Context;
use anyhow::bail;
use command_fds::{CommandFdExt, FdMapping};
use memfile::{CreateOptions, MemFile};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::rc::Rc;

trait TryUnzip<Output, E> {
    fn try_unzip(self) -> Result<Output, E>;
}

impl<It, Output, E, T> TryUnzip<Output, E> for It
where
    It: Iterator<Item = Result<T, E>>,
    Output: Extend<T> + Default,
{
    fn try_unzip(mut self) -> Result<Output, E> {
        self.try_fold(Output::default(), |mut c, r| {
            c.extend([r?]);
            Ok(c)
        })
    }
}

fn run_generator(
    command: &str,
    inputs: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> anyhow::Result<Vec<u8>> {
    let (args, fdmap): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .enumerate()
        .map(|(i, data)| -> anyhow::Result<(String, FdMapping)> {
            let fd = 3 + i;
            let mut file = MemFile::create("secret", CreateOptions::new())?;
            file.write_all(&data.as_ref())?;
            let mapping = FdMapping {
                parent_fd: file.into_fd(),
                child_fd: fd as i32,
            };
            Ok((format!("/dev/fd/{fd}"), mapping))
        })
        .try_unzip()?;

    let child = std::process::Command::new(command)
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::piped())
        .args(args)
        .fd_mappings(fdmap)?
        .spawn()?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("Generator failed");
    }

    Ok(output.stdout)
}

enum State {
    OnDisk(PathBuf),
    InMemory(Rc<Vec<u8>>),
    Missing,
}

impl State {
    fn load(&mut self, ctx: &Context) -> anyhow::Result<Rc<Vec<u8>>> {
        match *self {
            State::OnDisk(ref path) => {
                let data = Rc::new(ctx.decrypt(path)?);
                *self = State::InMemory(data.clone());
                Ok(data)
            }
            State::InMemory(ref data) => Ok(Rc::clone(data)),
            State::Missing => {
                panic!("missing secret");
            }
        }
    }
}

pub(crate) fn generate_secrets(ctx: &Context, force: bool, dry_run: bool) -> anyhow::Result<()> {
    use topo_sort::{SortResults, TopoSort};

    let mut todo = TopoSort::new();
    let mut cache: HashMap<&String, State> = HashMap::new();
    let mut secrets = HashMap::new();

    for (name, secret) in ctx.config.secrets.iter() {
        let path = ctx.root.join(&secret.path);
        if let Some(ref g) = secret.generator
            && (!path.exists() || force)
        {
            todo.insert(name, &g.dependencies);
            secrets.insert(name, (g, path));
            cache.insert(name, State::Missing);
        } else if path.exists() {
            cache.insert(name, State::OnDisk(path));
        } else {
            cache.insert(name, State::Missing);
        }
    }

    let SortResults::Full(todo) = todo.into_vec_nodes() else {
        bail!("Cycle detected");
    };

    for name in todo {
        println!("Generating {:?}", name);
        let (ref generator, ref path) = secrets[name];
        let dependencies = &generator.dependencies;
        let inputs = dependencies
            .iter()
            .map(|d| -> anyhow::Result<_> { Ok(cache.get_mut(d).unwrap().load(ctx)?.to_owned()) })
            .collect::<Result<Vec<_>, _>>()?;

        let plaintext = run_generator(&generator.command, inputs.iter().map(Rc::as_ref))?;
        if !dry_run {
            let ciphertext = ctx.encrypt_master(&plaintext)?;
            std::fs::write(path, ciphertext)?;
        }

        *cache.get_mut(name).unwrap() = State::InMemory(Rc::new(plaintext));
    }

    Ok(())
}
