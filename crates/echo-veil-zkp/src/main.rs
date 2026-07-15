use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use echo_veil_zkp::{
    ProofContext, decode_proof, decode_secret, encode_proof, generate_secret, prove, public_key,
    verify,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Deserialize)]
struct ProveInput {
    challenge_b64: String,
    provider_id: String,
    measurement: String,
    key_id: String,
}

#[derive(Deserialize)]
struct VerifyInput {
    proof_b64: String,
    provider_id: String,
    measurement: String,
    key_id: String,
}

#[derive(Serialize)]
struct KeyOutput {
    public_key_b64: String,
}

#[derive(Serialize)]
struct ProofOutput {
    proof_b64: String,
    public_key_b64: String,
}

#[derive(Serialize)]
struct VerifyOutput {
    valid: bool,
    challenge_b64: String,
    public_key_b64: String,
}

fn context(provider_id: String, measurement: String, key_id: String) -> ProofContext {
    ProofContext {
        provider_id,
        measurement,
        key_id,
    }
}

fn read_stdin<T: serde::de::DeserializeOwned>() -> Result<T, String> {
    let mut raw = Vec::new();
    io::stdin()
        .take(16 * 1024)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&raw).map_err(|_| "invalid input JSON".into())
}

fn key_file(args: &[String]) -> Result<PathBuf, String> {
    let position = args
        .iter()
        .position(|value| value == "--key-file")
        .ok_or_else(|| "--key-file is required".to_string())?;
    args.get(position + 1)
        .map(PathBuf::from)
        .ok_or_else(|| "--key-file requires a path".into())
}

fn public_keys_file(args: &[String]) -> Result<PathBuf, String> {
    let position = args
        .iter()
        .position(|value| value == "--public-keys-file")
        .ok_or_else(|| "--public-keys-file is required".to_string())?;
    args.get(position + 1)
        .map(PathBuf::from)
        .ok_or_else(|| "--public-keys-file requires a path".into())
}

fn load_allowed(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    let raw = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let values: Vec<String> = serde_json::from_str(&raw)
        .map_err(|_| "public key file must be a JSON string array".to_string())?;
    if values.is_empty() || values.len() > 1000 {
        return Err("public key allowlist must contain 1..1000 keys".into());
    }
    values
        .iter()
        .map(|value| {
            let decoded = URL_SAFE
                .decode(value)
                .map_err(|_| "invalid allowlisted public key".to_string())?;
            decoded
                .try_into()
                .map_err(|_| "invalid allowlisted public key length".into())
        })
        .collect()
}

fn write_private_key(path: &Path, value: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err("refusing to overwrite existing key file".into());
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| error.to_string())?;
        file.write_all(value).map_err(|error| error.to_string())?;
    }
    #[cfg(not(unix))]
    fs::write(path, value).map_err(|error| error.to_string())?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("");
    match command {
        "keygen" => {
            let path = key_file(&args)?;
            let mut secret = generate_secret().map_err(|error| error.to_string())?;
            let public = public_key(&secret).map_err(|error| error.to_string())?;
            let encoded = URL_SAFE.encode(secret);
            write_private_key(&path, encoded.as_bytes())?;
            secret.zeroize();
            println!(
                "{}",
                serde_json::to_string(&KeyOutput {
                    public_key_b64: URL_SAFE.encode(public)
                })
                .map_err(|error| error.to_string())?
            );
        }
        "public-key" => {
            let path = key_file(&args)?;
            let secret = decode_secret(&fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
            let public = public_key(&secret).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&KeyOutput {
                    public_key_b64: URL_SAFE.encode(public)
                })
                .map_err(|error| error.to_string())?
            );
        }
        "prove" => {
            let path = key_file(&args)?;
            let input: ProveInput = read_stdin()?;
            let challenge = URL_SAFE
                .decode(&input.challenge_b64)
                .map_err(|_| "invalid challenge_b64".to_string())?;
            let secret = decode_secret(&fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
            let public = public_key(&secret).map_err(|error| error.to_string())?;
            let proof = prove(
                &secret,
                &challenge,
                &context(input.provider_id, input.measurement, input.key_id),
            )
            .map_err(|error| error.to_string())?;
            let encoded = encode_proof(&proof).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&ProofOutput {
                    proof_b64: URL_SAFE.encode(encoded),
                    public_key_b64: URL_SAFE.encode(public),
                })
                .map_err(|error| error.to_string())?
            );
        }
        "verify" => {
            let allowed = load_allowed(&public_keys_file(&args)?)?;
            let input: VerifyInput = read_stdin()?;
            let proof_bytes = URL_SAFE
                .decode(&input.proof_b64)
                .map_err(|_| "invalid proof_b64".to_string())?;
            let proof = decode_proof(&proof_bytes).map_err(|error| error.to_string())?;
            let verified = verify(
                &proof,
                &context(input.provider_id, input.measurement, input.key_id),
                &allowed,
            )
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&VerifyOutput {
                    valid: true,
                    challenge_b64: URL_SAFE.encode(verified.challenge),
                    public_key_b64: URL_SAFE.encode(verified.public_key),
                })
                .map_err(|error| error.to_string())?
            );
        }
        _ => {
            return Err("usage: echo-veil-zkp <keygen|public-key|prove|verify> [options]".into());
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("echo-veil-zkp: {error}");
        std::process::exit(2);
    }
}
