use clap::{Parser, Subcommand};
use eyre::{ensure, Context, Result};
use libc::{tcsetattr, STDIN_FILENO, TCSAFLUSH};
use std::io::Write;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use tracing::trace;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use vault::{
    container::{ContainerFile, ContainerFileHeader},
    Vault,
};

fn getpass() -> Result<String> {
    let isatty = unsafe { libc::isatty(STDIN_FILENO) == 1 };
    let mut password = String::new();
    if isatty {
        unsafe {
            let mut old = MaybeUninit::<libc::termios>::uninit();
            let err = libc::tcgetattr(STDIN_FILENO, old.as_mut_ptr());
            ensure!(err == 0, "tcgetattr failed for stdin, but isatty is true");
            let mut new = old.assume_init();
            new.c_lflag &= !libc::ECHO;
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
            std::io::stdin().read_line(&mut password)?;
            tcsetattr(STDIN_FILENO, TCSAFLUSH, old.as_ptr());
        }
    } else {
        std::io::stdin().read_line(&mut password)?;
    }
    let endl = password.pop();
    ensure!(endl == Some('\n'), "Readline returned invalid string");
    ensure!(password.len() > 0, "Password cannot be empty");
    Ok(password)
}

fn ask_for_pass_or_cli(password: Option<String>) -> Result<String> {
    if let Some(password) = password {
        Ok(password)
    } else {
        print!("Please enter your password: ");
        std::io::stdout().flush()?;
        let password = getpass()?;
        println!();
        print!("Please repeat the password: ");
        std::io::stdout().flush()?;
        let password_repeat = getpass()?;
        ensure!(password == password_repeat, "Passwords don't match");
        Ok(password)
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Mount {
        #[arg(short = 'p', long)]
        password: Option<String>,
        #[arg(index = 1)]
        vault: PathBuf,
        #[arg(index = 2)]
        target: PathBuf,
    },
    Create {
        #[arg(short = 'p', long)]
        password: Option<String>,
        #[arg(index = 2)]
        target: PathBuf,
        #[arg(short = 'c', long)]
        block_count: u64,
        #[arg(long)]
        pbkdf2_iterations: Option<u32>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    trace!("Starting up vault cli");
    match cli.command {
        Command::Create {
            target,
            block_count,
            pbkdf2_iterations,
            password,
        } => {
            let password = ask_for_pass_or_cli(password)?;
            ContainerFile::create(
                target,
                &password,
                block_count as usize,
                pbkdf2_iterations.unwrap_or(ContainerFileHeader::PBKDF2_DEFAULT_ITERATIONS),
            )
            .wrap_err("Failed to create vault")?;
        }
        Command::Mount {
            vault,
            target,
            password,
        } => {
            if !target.is_dir() {
                println!("mount target {target:?} is not a directoy!");
                std::process::exit(1);
            }
            let is_empty = target.read_dir()?.next().is_none();
            if !is_empty {
                println!("mount target {target:?} is not empty!");
                std::process::exit(1);
            }
            if !vault.is_file() {
                println!("mount vault {vault:?} does not exist!");
                std::process::exit(1)
            }
            let password = ask_for_pass_or_cli(password)?;
            let mut vault = Vault::open(&vault, &password)?;
        }
    }
    Ok(())
}
