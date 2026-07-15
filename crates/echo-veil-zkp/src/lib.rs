//! A narrow Schnorr proof-of-possession protocol over Ristretto255.
//!
//! This proves knowledge of an allowlisted identity scalar without revealing it.
//! The Fiat-Shamir transcript binds the proof to the enclave-issued challenge and
//! the attested provider, measurement, and CKKS key identifiers.

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const TRANSCRIPT_LABEL: &[u8] = b"echo-veil-ristretto-schnorr-v1";
const MAX_CHALLENGE_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofContext {
    pub provider_id: String,
    pub measurement: String,
    pub key_id: String,
}

impl ProofContext {
    fn validate(&self) -> Result<(), ProofError> {
        for (name, value) in [
            ("provider_id", self.provider_id.as_str()),
            ("measurement", self.measurement.as_str()),
            ("key_id", self.key_id.as_str()),
        ] {
            if value.is_empty() || value.len() > 512 {
                return Err(ProofError(format!("invalid {name}")));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrProof {
    pub version: u8,
    pub challenge_b64: String,
    pub public_key_b64: String,
    pub commitment_b64: String,
    pub response_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub challenge: Vec<u8>,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError(pub String);

impl std::fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProofError {}

fn decode_fixed(value: &str, field: &str) -> Result<[u8; 32], ProofError> {
    let bytes = URL_SAFE
        .decode(value)
        .map_err(|_| ProofError(format!("invalid {}", field)))?;
    bytes
        .try_into()
        .map_err(|_| ProofError(format!("invalid {} length", field)))
}

fn decode_challenge(value: &str) -> Result<Vec<u8>, ProofError> {
    let challenge = URL_SAFE
        .decode(value)
        .map_err(|_| ProofError("invalid challenge_b64".into()))?;
    if challenge.len() < 32 || challenge.len() > MAX_CHALLENGE_BYTES {
        return Err(ProofError("invalid challenge length".into()));
    }
    Ok(challenge)
}

fn transcript_challenge(
    context: &ProofContext,
    challenge: &[u8],
    public_key: &[u8; 32],
    commitment: &[u8; 32],
) -> Scalar {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"provider-id", context.provider_id.as_bytes());
    transcript.append_message(b"measurement", context.measurement.as_bytes());
    transcript.append_message(b"key-id", context.key_id.as_bytes());
    transcript.append_message(b"challenge", challenge);
    transcript.append_message(b"public-key", public_key);
    transcript.append_message(b"commitment", commitment);
    let mut wide = Zeroizing::new([0_u8; 64]);
    transcript.challenge_bytes(b"schnorr-challenge", wide.as_mut());
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn generate_secret() -> Result<[u8; 32], ProofError> {
    loop {
        let mut wide = Zeroizing::new([0_u8; 64]);
        getrandom::fill(wide.as_mut())
            .map_err(|_| ProofError("operating-system randomness unavailable".into()))?;
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        if scalar != Scalar::ZERO {
            return Ok(scalar.to_bytes());
        }
    }
}

pub fn public_key(secret: &[u8; 32]) -> Result<[u8; 32], ProofError> {
    let scalar: Option<Scalar> = Scalar::from_canonical_bytes(*secret).into();
    let scalar = scalar.ok_or_else(|| ProofError("non-canonical secret scalar".into()))?;
    if scalar == Scalar::ZERO {
        return Err(ProofError("zero secret scalar".into()));
    }
    Ok((scalar * RISTRETTO_BASEPOINT_POINT).compress().to_bytes())
}

pub fn prove(
    secret: &[u8; 32],
    challenge: &[u8],
    context: &ProofContext,
) -> Result<SchnorrProof, ProofError> {
    context.validate()?;
    if challenge.len() < 32 || challenge.len() > MAX_CHALLENGE_BYTES {
        return Err(ProofError("invalid challenge length".into()));
    }
    let secret_scalar: Option<Scalar> = Scalar::from_canonical_bytes(*secret).into();
    let secret_scalar = secret_scalar.ok_or_else(|| ProofError("invalid secret scalar".into()))?;
    if secret_scalar == Scalar::ZERO {
        return Err(ProofError("zero secret scalar".into()));
    }
    let public_key = (secret_scalar * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    let nonce = loop {
        let mut wide = Zeroizing::new([0_u8; 64]);
        getrandom::fill(wide.as_mut())
            .map_err(|_| ProofError("operating-system randomness unavailable".into()))?;
        let candidate = Scalar::from_bytes_mod_order_wide(&wide);
        if candidate != Scalar::ZERO {
            break candidate;
        }
    };
    let commitment = (nonce * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let transcript_scalar = transcript_challenge(context, challenge, &public_key, &commitment);
    let response = nonce + transcript_scalar * secret_scalar;
    Ok(SchnorrProof {
        version: 1,
        challenge_b64: URL_SAFE.encode(challenge),
        public_key_b64: URL_SAFE.encode(public_key),
        commitment_b64: URL_SAFE.encode(commitment),
        response_b64: URL_SAFE.encode(response.to_bytes()),
    })
}

pub fn verify(
    proof: &SchnorrProof,
    context: &ProofContext,
    allowed_public_keys: &[[u8; 32]],
) -> Result<Verification, ProofError> {
    context.validate()?;
    if proof.version != 1 {
        return Err(ProofError("unsupported proof version".into()));
    }
    let challenge = decode_challenge(&proof.challenge_b64)?;
    let public_key_bytes = decode_fixed(&proof.public_key_b64, "public_key_b64")?;
    if !allowed_public_keys
        .iter()
        .any(|allowed| allowed == &public_key_bytes)
    {
        return Err(ProofError("public key is not allowlisted".into()));
    }
    let commitment_bytes = decode_fixed(&proof.commitment_b64, "commitment_b64")?;
    let response_bytes = decode_fixed(&proof.response_b64, "response_b64")?;
    let public_key = CompressedRistretto::from_slice(&public_key_bytes)
        .map_err(|_| ProofError("invalid public key".into()))?
        .decompress()
        .ok_or_else(|| ProofError("invalid public key".into()))?;
    let commitment = CompressedRistretto::from_slice(&commitment_bytes)
        .map_err(|_| ProofError("invalid commitment".into()))?
        .decompress()
        .ok_or_else(|| ProofError("invalid commitment".into()))?;
    let response: Option<Scalar> = Scalar::from_canonical_bytes(response_bytes).into();
    let response = response.ok_or_else(|| ProofError("invalid response scalar".into()))?;
    let transcript_scalar =
        transcript_challenge(context, &challenge, &public_key_bytes, &commitment_bytes);
    if response * RISTRETTO_BASEPOINT_POINT != commitment + transcript_scalar * public_key {
        return Err(ProofError("proof verification failed".into()));
    }
    Ok(Verification {
        challenge,
        public_key: public_key_bytes,
    })
}

pub fn decode_proof(value: &[u8]) -> Result<SchnorrProof, ProofError> {
    if value.len() > 4096 {
        return Err(ProofError("proof is too large".into()));
    }
    serde_json::from_slice(value).map_err(|_| ProofError("invalid proof JSON".into()))
}

pub fn encode_proof(proof: &SchnorrProof) -> Result<Vec<u8>, ProofError> {
    serde_json::to_vec(proof).map_err(|_| ProofError("could not serialize proof".into()))
}

pub fn decode_secret(value: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProofError> {
    let encoded = std::str::from_utf8(value)
        .map_err(|_| ProofError("key file is not UTF-8".into()))?
        .trim();
    let mut raw = URL_SAFE
        .decode(encoded)
        .map_err(|_| ProofError("key file is not valid base64".into()))?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err(ProofError("key file must contain a 32-byte scalar".into()));
    }
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(&raw);
    raw.zeroize();
    public_key(&output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ProofContext {
        ProofContext {
            provider_id: "azure-sev-snp-eastus2".into(),
            measurement: "approved-image".into(),
            key_id: "ckks-key-1".into(),
        }
    }

    #[test]
    fn round_trip_and_context_binding() {
        let secret = generate_secret().unwrap();
        let public = public_key(&secret).unwrap();
        let challenge = [7_u8; 32];
        let proof = prove(&secret, &challenge, &context()).unwrap();
        let verified = verify(&proof, &context(), &[public]).unwrap();
        assert_eq!(verified.challenge, challenge);
        assert_eq!(verified.public_key, public);

        let mut wrong = context();
        wrong.measurement = "other-image".into();
        assert!(verify(&proof, &wrong, &[public]).is_err());
    }

    #[test]
    fn rejects_tampering_and_unknown_keys() {
        let secret = generate_secret().unwrap();
        let proof = prove(&secret, &[9_u8; 32], &context()).unwrap();
        let unknown = public_key(&generate_secret().unwrap()).unwrap();
        assert!(verify(&proof, &context(), &[unknown]).is_err());

        let mut tampered = proof;
        tampered.challenge_b64 = URL_SAFE.encode([8_u8; 32]);
        assert!(verify(&tampered, &context(), &[public_key(&secret).unwrap()]).is_err());
    }
}
