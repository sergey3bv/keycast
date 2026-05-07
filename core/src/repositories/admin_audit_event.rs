// ABOUTME: Repository for durable admin-action audit events
// ABOUTME: Append-only forensic log capturing actor, action, target, and metadata

use chrono::DateTime;
use chrono::Utc;
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use crate::repositories::RepositoryError;

#[derive(Debug, Clone)]
pub struct AdminAuditEventRecord {
    pub tenant_id: i64,
    pub actor_pubkey: String,
    pub action: String,
    pub target_resource_type: String,
    pub target_resource_id: Option<String>,
    pub target_client_id: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone, FromRow)]
pub struct AdminAuditEventRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub tenant_id: i64,
    pub actor_pubkey: String,
    pub action: String,
    pub target_resource_type: String,
    pub target_resource_id: Option<String>,
    pub target_client_id: Option<String>,
    pub metadata_json: Value,
}

/// Optional filters for listing audit events within a single tenant.
#[derive(Debug, Clone, Default)]
pub struct AdminAuditEventListFilters {
    pub action: Option<String>,
    pub target_client_id: Option<String>,
    pub occurred_after: Option<DateTime<Utc>>,
    pub occurred_before: Option<DateTime<Utc>>,
    /// When `None`, defaults to 50. Clamped to 1..=200 in [`AdminAuditEventRepository::list_filtered`].
    pub limit: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AdminAuditEventRepository {
    pool: PgPool,
}

impl AdminAuditEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(
        &self,
        record: AdminAuditEventRecord,
    ) -> Result<AdminAuditEventRow, RepositoryError> {
        sqlx::query_as::<_, AdminAuditEventRow>(
            "INSERT INTO admin_audit_events (
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING
                id,
                occurred_at,
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json",
        )
        .bind(record.tenant_id)
        .bind(record.actor_pubkey)
        .bind(record.action)
        .bind(record.target_resource_type)
        .bind(record.target_resource_id)
        .bind(record.target_client_id)
        .bind(record.metadata_json)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_recent(
        &self,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<AdminAuditEventRow>, RepositoryError> {
        sqlx::query_as::<_, AdminAuditEventRow>(
            "SELECT
                id,
                occurred_at,
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json
             FROM admin_audit_events
             WHERE tenant_id = $1
             ORDER BY occurred_at DESC, id DESC
             LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_filtered(
        &self,
        tenant_id: i64,
        filters: AdminAuditEventListFilters,
    ) -> Result<Vec<AdminAuditEventRow>, RepositoryError> {
        let limit = filters.limit.unwrap_or(50).clamp(1, 200);
        let action = filters
            .action
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        let target_client_id = filters
            .target_client_id
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        sqlx::query_as::<_, AdminAuditEventRow>(
            "SELECT
                id,
                occurred_at,
                tenant_id,
                actor_pubkey,
                action,
                target_resource_type,
                target_resource_id,
                target_client_id,
                metadata_json
             FROM admin_audit_events
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR action = $2)
               AND ($3::text IS NULL OR target_client_id = $3)
               AND ($4::timestamptz IS NULL OR occurred_at >= $4)
               AND ($5::timestamptz IS NULL OR occurred_at <= $5)
             ORDER BY occurred_at DESC, id DESC
             LIMIT $6",
        )
        .bind(tenant_id)
        .bind(action.as_deref())
        .bind(target_client_id.as_deref())
        .bind(filters.occurred_after)
        .bind(filters.occurred_before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}
