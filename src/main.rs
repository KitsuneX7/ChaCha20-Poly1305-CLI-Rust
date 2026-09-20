use clap::{Parser, Subcommand};
use aead::AEAD;
use std::path::PathBuf;
use std::time::Instant;
use argon2::{Argon2, Algorithm, Version, Params};

#[derive(Parser)]
#[command(name = "aead", version = "1.0", about = "RFC 8439 ChaCha20-Poly1305 CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short = 'k', long = "key", conflicts_with = "key_file")]
        key: Option<String>,
        #[arg(short = 'K', long = "key-file", conflicts_with = "key")]
        key_file: Option<PathBuf>,
        #[arg(short = 'p', long = "password", conflicts_with_all = ["key", "key_file"])]
        password: Option<String>,
        #[arg(short = 'a', long = "aad", conflicts_with = "aad_file")]
        aad: Option<String>,
        #[arg(short = 'A', long = "aad-file", conflicts_with = "aad")]
        aad_file: Option<PathBuf>,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short = 'k', long = "key", conflicts_with = "key_file")]
        key: Option<String>,
        #[arg(short = 'K', long = "key-file", conflicts_with = "key")]
        key_file: Option<PathBuf>,
        #[arg(short = 'p', long = "password", conflicts_with_all = ["key", "key_file"])]
        password: Option<String>,
        #[arg(short = 'a', long = "aad", conflicts_with = "aad_file")]
        aad: Option<String>,
        #[arg(short = 'A', long = "aad-file", conflicts_with = "aad")]
        aad_file: Option<PathBuf>,
    }
}

fn derive_key_argon2id(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let params: Params = Params::new(0xFFFF, 3, 4, Some(32))
        .map_err(|e: argon2::Error| format!("Invalid Argon2 params: {e}"))?;
    let argon2: Argon2<'_> = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key: [u8; 32] = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e: argon2::Error| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

fn resolve_key(key_str: Option<String>, key_file: Option<PathBuf>, password: Option<String>, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    if let Some(s) = key_str {
        let bytes: Vec<u8> = hex::decode(s.trim()).map_err(|e: hex::FromHexError| format!("Invalid hex: {e}"))?;
        bytes.try_into().map_err(|_| "Key must be exactly 32 bytes (64 hex characters)".into())
    } else if let Some(path) = key_file {
        let hex_raw: String = std::fs::read_to_string(path).map_err(|e: std::io::Error| e.to_string())?;
        let bytes: Vec<u8> = hex::decode(hex_raw.trim()).map_err(|e: hex::FromHexError| format!("Invalid hex: {e}"))?;
        bytes.try_into().map_err(|_| "Key must be exactly 32 bytes (64 hex characters)".into())
    } else {
        let pass: String = match password {
            Some(p) => p,
            None => rpassword::prompt_password("Enter password: ")
                .map_err(|e: std::io::Error| format!("Failed to read password: {e}"))?,
        };
        derive_key_argon2id(&pass, salt)
    }
}

fn resolve_aad(aad_str: Option<String>, aad_file: Option<PathBuf>) -> Result<Vec<u8>, String> {
    if let Some(s) = aad_str {
        Ok(s.into_bytes())
    } else if let Some(path) = aad_file {
        std::fs::read(path).map_err(|e| format!("Failed to read AAD file: {e}"))
    } else {
        Ok(Vec::new())
    }
}

fn main() {
    let args: Cli = Cli::parse();
    match args.command {
        Commands::Encrypt { input, output, key, key_file, password, aad, aad_file } => {
            let salt: [u8; 16] = rand::random();
            let key_bytes: [u8; 32] = resolve_key(key, key_file, password, &salt).unwrap_or_else(|err: String| {
                eprintln!("Error resolving key: {err}");
                std::process::exit(1);
            });
            let aad_bytes: Vec<u8> = resolve_aad(aad, aad_file).unwrap_or_else(|err: String| {
                eprintln!("Error resolving AAD: {err}");
                std::process::exit(1);
            });
            let engine: AEAD = AEAD::new(key_bytes);
            let start: Instant = Instant::now();
            if let Err(err) = engine.encrypt_file(&input, &output, &aad_bytes, &salt) {
                eprintln!("Encryption error: {err}");
                std::process::exit(1);
            }
            let time: f64 = start.elapsed().as_secs_f64();
            println!("Successfully encrypted {} -> {} in {:.2} seconds", input.display(), output.display(), time);
        }
        Commands::Decrypt { input, output, key, key_file, password, aad, aad_file } => {
            let salt: [u8; 16] = AEAD::read_salt_from_file(&input).unwrap_or_else(|err: String| {
                eprintln!("Error reading header: {err}");
                std::process::exit(1);
            });
            let key_bytes: [u8; 32] = resolve_key(key, key_file, password, &salt).unwrap_or_else(|err: String| {
                eprintln!("Error resolving key: {err}");
                std::process::exit(1);
            });
            let aad_bytes: Vec<u8> = resolve_aad(aad, aad_file).unwrap_or_else(|err: String| {
                eprintln!("Error resolving AAD: {err}");
                std::process::exit(1);
            });
            let engine: AEAD = AEAD::new(key_bytes);
            let start: Instant = Instant::now();
            if let Err(err) = engine.decrypt_file(&input, &output, &aad_bytes) {
                eprintln!("Decryption error: {err}");
                std::process::exit(1);
            }
            let time: f64 = start.elapsed().as_secs_f64();
            println!("Successfully decrypted {} -> {} in {:.2} seconds", input.display(), output.display(), time);
        }
    }
}