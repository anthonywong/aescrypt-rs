// ============================================================================
// FILE: src/bin/aescrypt.rs
// Command-line interface for AES Crypt encryption and decryption.
// Supports macOS and Linux.
// ============================================================================

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    path::Path,
    process,
};

use clap::{Parser, Subcommand};

use aescrypt_rs::{
    constants::DEFAULT_PBKDF2_ITERATIONS, decrypt, encrypt, read_version, AescryptError,
    PasswordString,
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// AES Crypt command-line tool — encrypt and decrypt files using AES-256.
#[derive(Parser)]
#[command(name = "aescrypt-cli", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file or standard input
    Encrypt {
        /// Input file path; use '-' for standard input
        input: String,

        /// Output file path; use '-' for standard output
        output: String,

        /// Password (if omitted, you will be prompted interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Number of PBKDF2 iterations for key derivation [default: 300000]
        #[arg(short, long)]
        iterations: Option<u32>,
    },

    /// Decrypt a file or standard input
    Decrypt {
        /// Input file path; use '-' for standard input
        input: String,

        /// Output file path; use '-' for standard output
        output: String,

        /// Password (if omitted, you will be prompted interactively)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Print the AES Crypt format version of an encrypted file
    Version {
        /// Encrypted input file path; use '-' for standard input
        input: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
            iterations,
        } => run_encrypt(&input, &output, password, iterations),

        Commands::Decrypt {
            input,
            output,
            password,
        } => run_decrypt(&input, &output, password),

        Commands::Version { input } => run_version(&input),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn run_encrypt(
    input: &str,
    output: &str,
    password: Option<String>,
    iterations: Option<u32>,
) -> Result<(), AescryptError> {
    let iters = iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
    let pw = PasswordString::new(resolve_password(password, true)?);

    with_input(input, |reader| {
        with_output(output, |writer| encrypt(reader, writer, &pw, iters))
    })
}

fn run_decrypt(
    input: &str,
    output: &str,
    password: Option<String>,
) -> Result<(), AescryptError> {
    let pw = PasswordString::new(resolve_password(password, false)?);

    with_input(input, |reader| {
        with_output(output, |writer| decrypt(reader, writer, &pw))
    })
}

fn run_version(input: &str) -> Result<(), AescryptError> {
    with_input(input, |reader| {
        let v = read_version(reader)?;
        println!("{v}");
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Obtain the password: use the supplied value, or prompt the user on the
/// terminal.  When `confirm` is true (encrypt path) the user is asked to
/// enter the password twice.
fn resolve_password(
    supplied: Option<String>,
    confirm: bool,
) -> Result<String, AescryptError> {
    if let Some(pw) = supplied {
        return Ok(pw);
    }

    let pw = rpassword::prompt_password("Password: ")
        .map_err(AescryptError::Io)?;

    if confirm {
        let pw2 = rpassword::prompt_password("Confirm password: ")
            .map_err(AescryptError::Io)?;
        if pw != pw2 {
            return Err(AescryptError::Crypto("passwords do not match".into()));
        }
    }

    Ok(pw)
}

/// Open a reader for `path`.  When `path` is `"-"` standard input is used.
fn with_input<F, T>(path: &str, f: F) -> Result<T, AescryptError>
where
    F: FnOnce(&mut dyn io::Read) -> Result<T, AescryptError>,
{
    if path == "-" {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        f(&mut reader)
    } else {
        let file = File::open(Path::new(path))
            .map_err(AescryptError::Io)?;
        let mut reader = BufReader::new(file);
        f(&mut reader)
    }
}

/// Open a writer for `path`.  When `path` is `"-"` standard output is used.
fn with_output<F>(path: &str, f: F) -> Result<(), AescryptError>
where
    F: FnOnce(&mut dyn io::Write) -> Result<(), AescryptError>,
{
    if path == "-" {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        let result = f(&mut writer);
        // Flush explicitly so any I/O error surfaces here.
        writer.flush().map_err(AescryptError::Io)?;
        result
    } else {
        let file = File::create(Path::new(path))
            .map_err(AescryptError::Io)?;
        let mut writer = BufWriter::new(file);
        let result = f(&mut writer);
        writer.flush().map_err(AescryptError::Io)?;
        result
    }
}
