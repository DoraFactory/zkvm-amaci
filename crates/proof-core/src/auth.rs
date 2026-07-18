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

struct CachedAuthVerifier {
    public_key_hash: Field,
    public_key: AuthPublicKey,
    verifying_key: VerifyingKey<MlDsa65>,
}

pub struct CommandAuthVerifierCache {
    entries: Vec<CachedAuthVerifier>,
}

impl CommandAuthVerifierCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn verify(
        &mut self,
        expected_public_key_hash: &Field,
        public_key: &AuthPublicKey,
        signature: &AuthSignature,
        packed_command: &[Field; 3],
    ) -> ProofResult<bool> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| &entry.public_key_hash == expected_public_key_hash)
        {
            if &entry.public_key != public_key {
                return Ok(false);
            }
            return verify_with_key(&entry.verifying_key, signature, packed_command);
        }

        let public_key_hash = auth_public_key_hash(public_key);
        if &public_key_hash != expected_public_key_hash {
            return Ok(false);
        }
        let verifying_key = decode_verifying_key(public_key)?;
        let result = verify_with_key(&verifying_key, signature, packed_command)?;
        self.entries.push(CachedAuthVerifier {
            public_key_hash,
            public_key: public_key.clone(),
            verifying_key,
        });
        Ok(result)
    }
}

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

    let verifying_key = decode_verifying_key(public_key)?;
    verify_with_key(&verifying_key, signature, packed_command)
}

fn decode_verifying_key(public_key: &[u8]) -> ProofResult<VerifyingKey<MlDsa65>> {
    let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| ProofError::Crypto("invalid ML-DSA-65 public key length".to_string()))?;
    Ok(VerifyingKey::<MlDsa65>::decode(&encoded_key))
}

fn verify_with_key(
    verifying_key: &VerifyingKey<MlDsa65>,
    signature: &AuthSignature,
    packed_command: &[Field; 3],
) -> ProofResult<bool> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_cache_reuses_an_expanded_public_key() {
        let seed = Field::from(123u32);
        let first_command = [Field::from(1u32), Field::from(2u32), Field::from(3u32)];
        let second_command = [Field::from(4u32), Field::from(5u32), Field::from(6u32)];
        let (public_key, _) = auth_keypair_from_seed_for_testing(&seed);
        let public_key_hash = auth_public_key_hash(&public_key);
        let first_signature = sign_command_for_testing(&seed, &first_command);
        let second_signature = sign_command_for_testing(&seed, &second_command);
        let mut cache = CommandAuthVerifierCache::with_capacity(2);

        assert!(cache
            .verify(
                &public_key_hash,
                &public_key,
                &first_signature,
                &first_command,
            )
            .unwrap());
        assert!(cache
            .verify(
                &public_key_hash,
                &public_key,
                &second_signature,
                &second_command,
            )
            .unwrap());
        assert_eq!(cache.entries.len(), 1);

        let (different_public_key, _) = auth_keypair_from_seed_for_testing(&Field::from(456u32));
        assert!(!cache
            .verify(
                &public_key_hash,
                &different_public_key,
                &first_signature,
                &first_command,
            )
            .unwrap());
        assert_eq!(cache.entries.len(), 1);
    }
}
