use super::{KeyManager, KeyManagerError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::env;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub struct FileKeyManager {
    cipher: Aes256Gcm,
}

impl FileKeyManager {
    pub fn new() -> Result<Self, KeyManagerError> {
        let key = Self::load_key()?;
        let cipher = Aes256Gcm::new(&(*key).into());
        Ok(Self { cipher })
    }

    fn load_key() -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get parent directory")
            .to_path_buf();
        let key_path = project_root.join("master.key");

        // Wrap in Zeroizing so the string is zeroized after use
        let key_str = Zeroizing::new(
            std::fs::read_to_string(key_path)
                .map_err(|e| KeyManagerError::LoadKey(e.to_string()))?,
        );

        let key_bytes: [u8; 32] = BASE64
            .decode(key_str.trim())
            .map_err(|e| KeyManagerError::LoadKey(e.to_string()))?
            .try_into()
            .map_err(|_| KeyManagerError::LoadKey("Invalid key length".to_string()))?;

        Ok(Zeroizing::new(key_bytes))
    }
}

#[async_trait]
impl KeyManager for FileKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext_bytes)
            .map_err(|e| KeyManagerError::Encrypt(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        if ciphertext_bytes.len() < 12 {
            return Err(KeyManagerError::Decrypt("Ciphertext too short".to_string()));
        }

        let (nonce, encrypted) = ciphertext_bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| KeyManagerError::Decrypt(e.to_string()))?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[tokio::test]
    async fn test_key_encryption_decryption() -> Result<(), KeyManagerError> {
        // Create the key manager
        let key_manager = FileKeyManager::new()?;

        // Generate new Nostr keys
        let keys = Keys::generate();
        let secret_key_bytes = keys.secret_key().secret_bytes();
        let secret_key_vec = secret_key_bytes.to_vec();

        // Encrypt the secret key bytes
        let encrypted = key_manager.encrypt(&secret_key_bytes).await?;

        // Decrypt the encrypted bytes
        let decrypted = key_manager.decrypt(&encrypted).await?;

        // Verify the decrypted bytes match the original (Zeroizing derefs to Vec<u8>)
        assert_eq!(secret_key_vec, *decrypted);

        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_produces_different_ciphertexts() -> Result<(), KeyManagerError> {
        let key_manager = FileKeyManager::new()?;
        let keys = Keys::generate();
        let secret_key_bytes = keys.secret_key().secret_bytes();

        // Encrypt the same data twice
        let encrypted1 = key_manager.encrypt(&secret_key_bytes).await?;
        let encrypted2 = key_manager.encrypt(&secret_key_bytes).await?;

        // Verify we get different ciphertexts (due to different nonces)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same original data (Zeroizing derefs to Vec<u8>)
        let decrypted1 = key_manager.decrypt(&encrypted1).await?;
        let decrypted2 = key_manager.decrypt(&encrypted2).await?;
        assert_eq!(*decrypted1, *decrypted2);
        assert_eq!(&*decrypted1, &secret_key_bytes[..]);

        Ok(())
    }
}
