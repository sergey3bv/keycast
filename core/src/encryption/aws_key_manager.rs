use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;
use std::env;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

const MAX_KMS_RETRIES: u32 = 3;
const KMS_BASE_DELAY_MS: u64 = 100;

pub struct AwsKeyManager {
    client: Client,
    key_id: String,
}

impl AwsKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        let key_id = env::var("AWS_KMS_KEY_ID").map_err(|_| {
            KeyManagerError::ConfigurationError("AWS_KMS_KEY_ID not set".to_string())
        })?;
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        Self::from_config(&key_id, &region).await
    }

    pub async fn from_config(key_id: &str, region: &str) -> Result<Self, KeyManagerError> {
        if key_id.trim().is_empty() {
            return Err(KeyManagerError::ConfigurationError(
                "AWS_KMS_KEY_ID cannot be empty".to_string(),
            ));
        }

        let region = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region
        };

        info!("Initializing AWS KMS client");
        debug!("Region: {}, Key ID: {}", region, key_id);

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .load()
            .await;
        let client = Client::new(&config);

        info!("AWS KMS client initialized successfully");

        Ok(Self {
            client,
            key_id: key_id.to_string(),
        })
    }
}

#[async_trait]
impl KeyManager for AwsKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        debug!("Encrypting {} bytes with AWS KMS", plaintext_bytes.len());

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match self
                .client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(Blob::new(plaintext_bytes))
                .send()
                .await
            {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS encrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    error!("KMS encrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::EncryptionError(format!(
                        "KMS encryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let ciphertext = response.ciphertext_blob().ok_or_else(|| {
            KeyManagerError::EncryptionError("KMS encryption returned empty ciphertext".to_string())
        })?;
        let ciphertext_bytes = ciphertext.as_ref().to_vec();
        debug!("Successfully encrypted to {} bytes", ciphertext_bytes.len());

        Ok(ciphertext_bytes)
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        debug!("Decrypting {} bytes with AWS KMS", ciphertext_bytes.len());

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match self
                .client
                .decrypt()
                .ciphertext_blob(Blob::new(ciphertext_bytes))
                .send()
                .await
            {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS decrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    error!("KMS decrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::DecryptionError(format!(
                        "KMS decryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let plaintext = response.plaintext().ok_or_else(|| {
            KeyManagerError::DecryptionError("KMS decryption returned empty plaintext".to_string())
        })?;
        let plaintext_bytes = plaintext.as_ref().to_vec();
        debug!("Successfully decrypted to {} bytes", plaintext_bytes.len());

        Ok(Zeroizing::new(plaintext_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_new_requires_key_id() {
        std::env::remove_var("AWS_KMS_KEY_ID");
        let result = AwsKeyManager::new().await;
        assert!(matches!(
            result,
            Err(KeyManagerError::ConfigurationError(msg)) if msg.contains("AWS_KMS_KEY_ID not set")
        ));
    }

    #[tokio::test]
    async fn test_from_config_rejects_empty_key_id() {
        let result = AwsKeyManager::from_config("", "us-east-1").await;
        assert!(matches!(
            result,
            Err(KeyManagerError::ConfigurationError(msg)) if msg.contains("cannot be empty")
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_encrypt_decrypt_roundtrip() {
        if env::var("AWS_KMS_KEY_ID").is_err() {
            return;
        }

        let manager = AwsKeyManager::new()
            .await
            .expect("Failed to create AWS key manager");
        let plaintext = b"test data for aws kms encryption";

        let ciphertext = manager.encrypt(plaintext).await.expect("Encryption failed");
        let decrypted = manager
            .decrypt(&ciphertext)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
