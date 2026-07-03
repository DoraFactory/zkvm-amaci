use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::native_types::{field_to_digest, NativeCommand};
use crate::types::{AuthPublicKey, AuthSignature};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use sha2::{Digest as Sha2Digest, Sha256};

const AUTH_KEY_HASH_DOMAIN: &[u8] = b"AMACI_ZKVM_ML_DSA65_AUTH_KEY_V1";
const AUTH_SEED_DOMAIN: &[u8] = b"AMACI_ZKVM_ML_DSA65_TEST_SEED_V1";

pub fn auth_public_key_hash(public_key: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_KEY_HASH_DOMAIN);
    hasher.update((public_key.len() as u64).to_be_bytes());
    hasher.update(public_key);
    Field::from_be_bytes(hasher.finalize().into())
}

pub fn verify_command_auth_signature(
    expected_public_key_hash: &Field,
    public_key: &AuthPublicKey,
    signature: &AuthSignature,
    packed_command: &[Field; 3],
) -> ProofResult<bool> {
    if &auth_public_key_hash(public_key) != expected_public_key_hash {
        return Ok(false);
    }

    let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice())
        .map_err(|_| ProofError::Crypto("invalid ML-DSA-65 public key length".to_string()))?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
    let signature = Signature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| ProofError::Crypto("invalid ML-DSA-65 signature".to_string()))?;
    Ok(verifying_key
        .verify(&command_message(packed_command)?, &signature)
        .is_ok())
}

pub fn command_message(packed_command: &[Field; 3]) -> ProofResult<[u8; 32]> {
    Ok(NativeCommand::from_packed_fields(packed_command)?.message_digest())
}

pub fn auth_keypair_from_seed_for_testing(seed: &Field) -> (AuthPublicKey, SigningKey<MlDsa65>) {
    let ml_seed = ml_dsa::Seed::from(auth_seed(seed));
    let signing_key = SigningKey::<MlDsa65>::from_seed(&ml_seed);
    let public_key = signing_key.verifying_key().encode().to_vec();
    (public_key, signing_key)
}

pub fn sign_command_for_testing(seed: &Field, packed_command: &[Field; 3]) -> AuthSignature {
    let (_, signing_key) = auth_keypair_from_seed_for_testing(seed);
    let signature: Signature<MlDsa65> = signing_key
        .sign(&command_message(packed_command).expect("test command fields fit native widths"));
    signature.to_bytes().to_vec()
}

fn auth_seed(seed: &Field) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_SEED_DOMAIN);
    hasher.update(field_to_digest(seed));
    hasher.finalize().into()
}
