//! Atomic re-sealing of every credential class owned by PostgreSQL.

use sqlx::Row;

use super::{DbError, decode_managed_settings, insert_audit_log_with, stored_network_kind};

/// Counts from one atomic database-wide master-key rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretRotationReport {
    pub managed_config_secrets: usize,
    pub account_network_secrets: usize,
}

fn reseal(
    value: &mut String,
    context: &[u8],
    keys: &crate::secret::SecretKeyring,
    boundary: &str,
) -> Result<bool, DbError> {
    if value.is_empty() {
        return Ok(false);
    }
    if !crate::secret::is_sealed(value) {
        return Err(DbError::SecretRotation(format!(
            "{boundary} contains plaintext instead of a sealed value"
        )));
    }
    let plaintext = keys.open(value, context).map_err(|error| {
        DbError::SecretRotation(format!("{boundary} cannot be decrypted: {error}"))
    })?;
    *value = keys.seal(&plaintext, context);
    Ok(true)
}

/// Re-seal every database-owned credential with the keyring's primary key in
/// one transaction.
///
/// The caller must configure the new key as the deployment primary and retain
/// the old key in `previous_key_files` before running this operation.
/// PostgreSQL row locks serialize control-plane/network writes; any unreadable,
/// plaintext, or structurally invalid secret aborts the whole transaction.
pub async fn rotate_database_secrets(
    pool: &sqlx::PgPool,
    keys: &crate::secret::SecretKeyring,
    actor: &str,
) -> Result<SecretRotationReport, DbError> {
    if keys.key_count() < 2 {
        return Err(DbError::SecretRotation(
            "rotation requires a primary key and at least one previous key".into(),
        ));
    }

    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let settings_row =
        sqlx::query("SELECT revision, settings FROM server_settings WHERE singleton FOR UPDATE")
            .fetch_optional(&mut *transaction)
            .await
            .map_err(DbError::Query)?
            .ok_or_else(|| {
                DbError::SecretRotation(
                    "server settings are not initialized; start e6ircd once before rotation".into(),
                )
            })?;
    let revision: i64 = settings_row.get("revision");
    let mut settings = decode_managed_settings(settings_row.get("settings"))?;
    let mut managed_config_secrets = 0usize;
    for provider in &mut settings.oidc_providers {
        managed_config_secrets += reseal(
            &mut provider.client_secret,
            crate::secret::CONFIG_CONTEXT,
            keys,
            &format!("OpenID Connect provider {:?}", provider.name),
        )? as usize;
    }
    for oper in &mut settings.opers {
        managed_config_secrets += reseal(
            &mut oper.password,
            crate::secret::CONFIG_CONTEXT,
            keys,
            &format!("IRC operator {:?}", oper.name),
        )? as usize;
    }
    for network in &mut settings.networks {
        if let Some(password) = &mut network.sasl_password {
            managed_config_secrets += reseal(
                password,
                crate::secret::CONFIG_CONTEXT,
                keys,
                &format!("managed network {:?} password", network.name),
            )? as usize;
        }
        if network.kind.account_is_secret()
            && let Some(account) = &mut network.sasl_account
        {
            managed_config_secrets += reseal(
                account,
                crate::secret::CONFIG_CONTEXT,
                keys,
                &format!("managed network {:?} account token", network.name),
            )? as usize;
        }
    }
    let settings_value = serde_json::to_value(&settings)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    sqlx::query(
        "UPDATE server_settings
         SET revision = revision + 1, settings = $2, updated_by = $3, updated_at = now()
         WHERE singleton AND revision = $1",
    )
    .bind(revision)
    .bind(settings_value)
    .bind(actor)
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;

    let network_rows = sqlx::query(
        "SELECT n.id, a.name AS owner, n.name, n.kind, n.sasl_account,
                n.sasl_password_sealed
         FROM bnc_networks n
         JOIN accounts a ON a.id = n.account_id
         ORDER BY n.id
         FOR UPDATE OF n",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    let mut account_network_secrets = 0usize;
    for row in network_rows {
        let id: i64 = row.get("id");
        let owner: String = row.get("owner");
        let name: String = row.get("name");
        let kind = stored_network_kind(&row.get::<String, _>("kind"))?;
        let context = crate::bouncer::bnc_secret_context(&owner);
        let mut account: Option<String> = row.get("sasl_account");
        let mut password: Option<String> = row.get("sasl_password_sealed");
        if kind.account_is_secret()
            && let Some(value) = &mut account
        {
            account_network_secrets += reseal(
                value,
                &context,
                keys,
                &format!("account {owner:?} network {name:?} account token"),
            )? as usize;
        }
        if let Some(value) = &mut password {
            account_network_secrets += reseal(
                value,
                &context,
                keys,
                &format!("account {owner:?} network {name:?} password"),
            )? as usize;
        }
        sqlx::query(
            "UPDATE bnc_networks
             SET sasl_account = $2, sasl_password_sealed = $3
             WHERE id = $1",
        )
        .bind(id)
        .bind(account)
        .bind(password)
        .execute(&mut *transaction)
        .await
        .map_err(DbError::Query)?;
    }

    insert_audit_log_with(
        &mut *transaction,
        actor,
        "SECRET_ROTATE",
        "server",
        &format!(
            "re-sealed {managed_config_secrets} managed and \
             {account_network_secrets} account-network secrets"
        ),
    )
    .await?;
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(SecretRotationReport {
        managed_config_secrets,
        account_network_secrets,
    })
}
