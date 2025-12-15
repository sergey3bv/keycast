// ABOUTME: Repository module for data access operations
// ABOUTME: Provides abstraction layer between handlers and database

mod authorization;
mod error;
mod oauth_authorization;
mod oauth_code;
mod personal_keys;
mod policy;
mod signing_activity;
mod stored_key;
mod team;
mod user;

pub use authorization::AuthorizationRepository;
pub use error::RepositoryError;
pub use oauth_authorization::{CreateOAuthAuthorizationParams, OAuthAuthorizationRepository};
pub use oauth_code::{
    OAuthCodeData, OAuthCodeRepository, StoreOAuthCodeParams, StoreOAuthCodeWithRegistrationParams,
};
pub use personal_keys::PersonalKeysRepository;
pub use policy::PolicyRepository;
pub use signing_activity::SigningActivityRepository;
pub use stored_key::StoredKeyRepository;
pub use team::TeamRepository;
pub use user::{UserRepository, VerificationTokenData};
