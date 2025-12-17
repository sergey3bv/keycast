// ABOUTME: Type aliases for memory-safe secret handling
// ABOUTME: Wraps secrets in types that auto-zeroize memory on drop

pub use secrecy::{ExposeSecret, SecretString};
pub use zeroize::Zeroizing;

/// Decrypted secret key bytes - auto-zeroizes on drop.
/// Use this for all `key_manager.decrypt()` results.
pub type DecryptedSecret = Zeroizing<Vec<u8>>;

/// Connection secret for NIP-46 - provides Debug redaction + auto-zeroize on drop.
pub type ConnectionSecret = SecretString;

/// Decrypted plaintext from NIP-04/NIP-44 - auto-zeroizes on drop.
/// Use `.expose_secret()` only at the point where plaintext must be serialized/returned.
pub type DecryptedPlaintext = SecretString;
