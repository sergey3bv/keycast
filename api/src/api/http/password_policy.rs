const MIN_PASSWORD_LENGTH: usize = 8;
const WEAK_PASSWORD_CODE: &str = "WEAK_PASSWORD";
const WEAK_PASSWORD_MESSAGE: &str = "Password does not meet security requirements.";

const COMMON_WEAK_PASSWORDS: [&str; 3] = ["1234", "password", "password123"];

#[derive(Debug, Clone)]
pub struct PasswordPolicyError {
    code: &'static str,
    message: &'static str,
}

impl PasswordPolicyError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    fn weak_password() -> Self {
        Self {
            code: WEAK_PASSWORD_CODE,
            message: WEAK_PASSWORD_MESSAGE,
        }
    }
}

pub fn validate_new_password(password: &str) -> Result<(), PasswordPolicyError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(PasswordPolicyError::weak_password());
    }

    let normalized = password.trim().to_ascii_lowercase();
    if COMMON_WEAK_PASSWORDS.contains(&normalized.as_str()) {
        return Err(PasswordPolicyError::weak_password());
    }

    Ok(())
}
