#![allow(unused)]

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use zeroize::Zeroizing;

pub struct AwsKeyManager {
    // Add AWS KMS client here
}

impl AwsKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        // Initialize AWS KMS client here
        todo!("Implement AWS KMS client initialization")
    }
}

#[async_trait]
impl KeyManager for AwsKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        todo!("Implement AWS KMS encryption")
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        todo!("Implement AWS KMS decryption")
    }
}
