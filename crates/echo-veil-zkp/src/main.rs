use std::{
    collections::HashSet,
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use echo_veil_zkp::{
    ProofContext, decode_proof, decode_secret, encode_proof, generate_secret, prove, public_key,
    validate_public_key, verify,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAX_STDIN_BYTES: u64 = 16 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 512;
const MAX_ALLOWLIST_FILE_BYTES: u64 = 128 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveInput {
    challenge_b64: String,
    provider_id: String,
    measurement: String,
    key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    read_json(io::stdin(), MAX_STDIN_BYTES)
}

fn read_json<T: serde::de::DeserializeOwned, R: Read>(
    reader: R,
    maximum: u64,
) -> Result<T, String> {
    let mut raw = Vec::new();
    reader
        .take(maximum + 1)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > maximum {
        return Err("input exceeds the safety limit".into());
    }
    serde_json::from_slice(&raw).map_err(|_| "invalid input JSON".into())
}

fn reject_symlink_components(path: &Path, label: &str) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|_| format!("{label} path is unavailable"))?
            .join(path)
    };
    for component in absolute.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{label} path must not contain symbolic links"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(format!("{label} path is unavailable")),
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    reject_symlink_components(path, label)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} is unreadable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!("{label} is not a bounded regular file"));
    }
    let mut raw = Vec::new();
    fs::File::open(path)
        .map_err(|_| format!("{label} is unreadable"))?
        .take(maximum + 1)
        .read_to_end(&mut raw)
        .map_err(|_| format!("{label} is unreadable"))?;
    if raw.len() as u64 > maximum {
        return Err(format!("{label} exceeds the safety limit"));
    }
    Ok(raw)
}

fn read_secret_key(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "key file is unreadable".to_string())?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("key file must be owner-only".into());
        }
    }
    read_bounded_file(path, MAX_KEY_FILE_BYTES, "key file")
}

fn key_file(args: &[String]) -> Result<PathBuf, String> {
    if args.len() != 3 || args.get(1).map(String::as_str) != Some("--key-file") {
        return Err("exactly --key-file <path> is required".into());
    }
    args.get(2)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "--key-file requires a path".into())
}

fn public_keys_file(args: &[String]) -> Result<PathBuf, String> {
    if args.len() != 3 || args.get(1).map(String::as_str) != Some("--public-keys-file") {
        return Err("exactly --public-keys-file <path> is required".into());
    }
    args.get(2)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "--public-keys-file requires a path".into())
}

fn load_allowed(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "public key allowlist is unreadable".to_string())?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("public key allowlist must not be group/world writable".into());
        }
    }
    let raw = read_bounded_file(path, MAX_ALLOWLIST_FILE_BYTES, "public key allowlist")?;
    let values: Vec<String> = serde_json::from_slice(&raw)
        .map_err(|_| "public key file must be a JSON string array".to_string())?;
    if values.is_empty() || values.len() > 1000 {
        return Err("public key allowlist must contain 1..1000 keys".into());
    }
    let decoded = values
        .iter()
        .map(|value| {
            let decoded = URL_SAFE
                .decode(value)
                .map_err(|_| "invalid allowlisted public key".to_string())?;
            if URL_SAFE.encode(&decoded) != *value {
                return Err("invalid allowlisted public key".into());
            }
            let key = decoded
                .try_into()
                .map_err(|_| "invalid allowlisted public key length".to_string())?;
            validate_public_key(&key).map_err(|_| "invalid allowlisted public key".to_string())?;
            Ok(key)
        })
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    let unique = decoded.iter().copied().collect::<HashSet<_>>();
    if unique.len() != decoded.len() {
        return Err("public key allowlist must not contain duplicates".into());
    }
    Ok(decoded)
}

fn write_private_key(path: &Path, value: &[u8]) -> Result<(), String> {
    reject_symlink_components(path, "key file")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "refusing to overwrite or create key file".to_string())?;
    file.write_all(value).map_err(|error| error.to_string())?;
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
            let encoded = zeroize::Zeroizing::new(URL_SAFE.encode(secret));
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
            let secret =
                decode_secret(&read_secret_key(&path)?).map_err(|error| error.to_string())?;
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
            if URL_SAFE.encode(&challenge) != input.challenge_b64 {
                return Err("invalid challenge_b64".into());
            }
            let secret =
                decode_secret(&read_secret_key(&path)?).map_err(|error| error.to_string())?;
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
            if URL_SAFE.encode(&proof_bytes) != input.proof_b64 {
                return Err("invalid proof_b64".into());
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_json_rejects_truncated_or_unknown_input() {
        let oversized = br#"{"challenge_b64":"value","provider_id":"p","measurement":"m","key_id":"k"} trailing"#;
        assert!(read_json::<ProveInput, _>(&oversized[..], 16).is_err());

        let unknown = br#"{"challenge_b64":"value","provider_id":"p","measurement":"m","key_id":"k","extra":true}"#;
        assert!(read_json::<ProveInput, _>(&unknown[..], 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_creation_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = directory.path().join("linked");
        symlink(&real, &linked).unwrap();

        assert!(write_private_key(&linked.join("identity.key"), b"secret").is_err());
    }

    #[test]
    fn public_key_allowlist_rejects_the_ristretto_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("allowed.json");
        let encoded = URL_SAFE.encode([0_u8; 32]);
        fs::write(&path, serde_json::to_vec(&vec![encoded]).unwrap()).unwrap();

        assert_eq!(
            load_allowed(&path).unwrap_err(),
            "invalid allowlisted public key"
        );
    }
}
