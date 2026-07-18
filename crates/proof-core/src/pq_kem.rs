use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::native_types::field_to_digest;
use crate::types::{KemCiphertext, KemPublicKey, PubKey};
use ml_kem::{
    kem::{Decapsulate, KeyExport},
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32,
};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

const KEM_SEED_DOMAIN: &[u8] = b"AMACI_ZKVM_ML_KEM768_SEED_V1";
const KEM_ENCAPS_DOMAIN: &[u8] = b"AMACI_ZKVM_ML_KEM768_ENCAPS_V1";
const KEM_COMPACT_DOMAIN: &[u8] = b"AMACI_ZKVM_ML_KEM768_COMPACT_V1";

type MlKem768DecapsulationKey = DecapsulationKey<MlKem768>;
type MlKem768EncapsulationKey = EncapsulationKey<MlKem768>;

pub struct KemDecapsulator {
    key: MlKem768DecapsulationKey,
}

impl KemDecapsulator {
    pub fn from_seed(seed: &Field) -> Self {
        Self {
            key: MlKem768DecapsulationKey::from_seed(Seed::from(kem_seed(seed))),
        }
    }

    pub fn public_key(&self) -> KemPublicKey {
        let bytes = self.key.encapsulation_key().to_bytes();
        fixed_public_key(bytes.as_ref())
    }

    pub fn compact_public_key(&self) -> PubKey {
        kem_public_key_compact(&self.public_key())
    }

    pub fn decapsulate_to_fields(&self, ciphertext: &KemCiphertext) -> ProofResult<[Field; 2]> {
        let ciphertext = Ciphertext::<MlKem768>::try_from(ciphertext.as_ref())
            .map_err(|_| ProofError::Crypto("invalid ML-KEM-768 ciphertext length".to_string()))?;
        let shared_key = self.key.decapsulate(&ciphertext);
        Ok(shared_key_to_fields(shared_key.as_ref()))
    }
}

pub fn private_to_pub_key(formatted_priv_key: &Field) -> PubKey {
    KemDecapsulator::from_seed(formatted_priv_key).compact_public_key()
}

pub fn kem_public_key_from_seed_for_testing(seed: &Field) -> KemPublicKey {
    KemDecapsulator::from_seed(seed).public_key()
}

pub fn encapsulate_to_seed_for_testing(
    recipient_seed: &Field,
    randomness: &Field,
) -> ProofResult<(KemCiphertext, PubKey, [Field; 2])> {
    let public_key = kem_public_key_from_seed_for_testing(recipient_seed);
    encapsulate_to_public_key_for_testing(&public_key, randomness)
}

pub fn encapsulate_to_public_key_for_testing(
    public_key: &KemPublicKey,
    randomness: &Field,
) -> ProofResult<(KemCiphertext, PubKey, [Field; 2])> {
    let (ciphertext, shared_key) =
        encapsulate_raw_to_public_key_for_testing(public_key, randomness)?;
    let compact = kem_ciphertext_compact(&ciphertext);
    Ok((ciphertext, compact, shared_key))
}

pub(crate) fn encapsulate_raw_to_public_key_for_testing(
    public_key: &KemPublicKey,
    randomness: &Field,
) -> ProofResult<(KemCiphertext, [Field; 2])> {
    let key = ml_kem::kem::Key::<MlKem768EncapsulationKey>::try_from(public_key.as_ref())
        .map_err(|_| ProofError::Crypto("invalid ML-KEM-768 public key length".to_string()))?;
    let encapsulation_key = MlKem768EncapsulationKey::new(&key)
        .map_err(|_| ProofError::Crypto("invalid ML-KEM-768 public key".to_string()))?;
    let (ciphertext, shared_key) =
        encapsulation_key.encapsulate_deterministic(&B32::from(encapsulation_seed(randomness)));
    let ciphertext = fixed_ciphertext(ciphertext.as_ref());
    Ok((ciphertext, shared_key_to_fields(shared_key.as_ref())))
}

pub fn decapsulate_to_fields(
    recipient_seed: &Field,
    ciphertext: &KemCiphertext,
) -> ProofResult<[Field; 2]> {
    KemDecapsulator::from_seed(recipient_seed).decapsulate_to_fields(ciphertext)
}

pub fn kem_public_key_compact(public_key: &KemPublicKey) -> PubKey {
    compact_pair(b"public-key", public_key.as_ref())
}

pub fn kem_ciphertext_compact(ciphertext: &KemCiphertext) -> PubKey {
    compact_pair(b"ciphertext", ciphertext.as_ref())
}

pub fn deactivate_ciphertext_fields(ciphertext: &KemCiphertext) -> (PubKey, PubKey) {
    (
        compact_pair(b"deactivate-c1", ciphertext.as_ref()),
        compact_pair(b"deactivate-c2", ciphertext.as_ref()),
    )
}

fn fixed_public_key(bytes: &[u8]) -> KemPublicKey {
    KemPublicKey::from_slice(bytes).expect("ML-KEM produced fixed public key length")
}

fn fixed_ciphertext(bytes: &[u8]) -> KemCiphertext {
    KemCiphertext::from_slice(bytes).expect("ML-KEM produced fixed ciphertext length")
}

pub fn shared_key_hash_fields(shared_key: &[Field; 2]) -> Field {
    crate::hash_backend::hash_fields(shared_key)
}

fn kem_seed(seed: &Field) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(KEM_SEED_DOMAIN);
    hasher.update(field_to_digest(seed));
    hasher.finalize().into()
}

fn encapsulation_seed(randomness: &Field) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEM_ENCAPS_DOMAIN);
    hasher.update(field_to_digest(randomness));
    hasher.finalize().into()
}

fn shared_key_to_fields(shared_key: &[u8]) -> [Field; 2] {
    [
        Field::from_be_slice(&shared_key[0..16]),
        Field::from_be_slice(&shared_key[16..32]),
    ]
}

fn compact_pair(label: &[u8], bytes: &[u8]) -> PubKey {
    [
        compact_field(label, 0, bytes),
        compact_field(label, 1, bytes),
    ]
}

fn compact_field(label: &[u8], index: u8, bytes: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(KEM_COMPACT_DOMAIN);
    hasher.update(label);
    hasher.update([index]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Field::from_be_bytes(hasher.finalize().into())
}
