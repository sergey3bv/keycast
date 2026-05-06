//! Postgres URL resolution and safety checks for signer integration tests.
//!
//! Prefer [`connect_pool`] so tests use an isolated database, not the normal app DB.
//!
//! - Set **`TEST_DATABASE_URL`** to a dedicated Postgres database (recommended).
//! - If only **`DATABASE_URL`** is set, the database name must end with `_test` so
//!   accidental use of a `.../keycast` dev database is rejected.
//! - If neither is set, defaults to `postgres://postgres:password@localhost/keycast_test`.
//!
//! Does not run migrations; run `sqlx migrate run` (or project scripts) against the same URL first.
//! CI applies `database/migrations` before running tests.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

const DEFAULT_URL: &str = "postgres://postgres:password@localhost/keycast_test";

/// Resolves the connection string used by signer integration tests.
pub fn resolved_database_url() -> String {
    let from_test_env = std::env::var("TEST_DATABASE_URL").ok();
    let from_database_env = std::env::var("DATABASE_URL").ok();
    let used_explicit_test_url = from_test_env.is_some();

    let url = match (from_test_env, from_database_env) {
        (Some(u), _) => u,
        (None, Some(u)) => u,
        (None, None) => DEFAULT_URL.to_string(),
    };

    assert_safe_for_integration_tests(&url);

    if !used_explicit_test_url {
        assert_database_name_suggests_test_db(&url);
    }

    url
}

/// Validates that the URL points to a local database only (mirrors API integration test guards).
pub fn assert_safe_for_integration_tests(url: &str) {
    let host_info = url
        .split('@')
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("unknown");

    let production_indicators = [
        "keycast-db",
        "cloudsql",
        "prod",
        "130.211.",
        "35.192.",
        "35.188.",
        "35.193.",
        "34.66.",
        "34.67.",
        ".gcp.",
        ".cloud.",
        "rds.amazonaws",
        "azure",
    ];

    let url_lower = url.to_lowercase();
    for indicator in production_indicators {
        assert!(
            !url_lower.contains(indicator),
            "\n\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║  REFUSING TO RUN: database URL appears to be a production DB     ║\n\
            ║                                                                  ║\n\
            ║  Detected production indicator: {:<32} ║\n\
            ║                                                                  ║\n\
            ║  Tests must NEVER run against production databases.              ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n\n",
            indicator
        );
    }

    let is_local = url_lower.contains("localhost")
        || url_lower.contains("127.0.0.1")
        || url_lower.contains("host.docker.internal")
        || (host_info.contains("postgres") && !host_info.contains('.'));

    assert!(
        is_local,
        "\n\n\
        ╔══════════════════════════════════════════════════════════════════╗\n\
        ║  REFUSING TO RUN: database URL must point to a local database    ║\n\
        ║  Host: {:<55} ║\n\
        ╚══════════════════════════════════════════════════════════════════╝\n\n",
        host_info
    );
}

/// When `TEST_DATABASE_URL` is not set, require a database name ending with `_test`.
fn assert_database_name_suggests_test_db(url: &str) {
    let Some(name) = postgres_database_name(url) else {
        panic!(
            "Could not parse database name from URL; set TEST_DATABASE_URL explicitly.\n\
             URL (host only): {}",
            url.split('@').nth(1).unwrap_or("?")
        );
    };
    assert!(
        name.ends_with("_test"),
        "\n\n\
        Signer integration tests require an isolated database.\n\
        Database name `{name}` does not end with `_test`.\n\
        Set TEST_DATABASE_URL to a dedicated test database, or set DATABASE_URL to one whose name ends with `_test` (e.g. keycast_test).\n"
    );
}

fn postgres_database_name(url: &str) -> Option<&str> {
    let path = url.split('@').nth(1)?.split('/').nth(1)?;
    let name = path.split('?').next()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Connects after URL resolution and safety checks. Does not run migrations.
pub async fn connect_pool() -> PgPool {
    let database_url = resolved_database_url();
    PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Failed to connect for signer integration tests: {e}\n\
                 URL resolved from TEST_DATABASE_URL / DATABASE_URL / default.\n\
                 Ensure Postgres is running and migrations have been applied."
            );
        })
}
