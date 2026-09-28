//! The roster of edges (`core_edges`, DESIGN §19.3): the slot each edge's
//! connection identifiers carry, kept across links and across cores.

use sqlx::PgPool;

use super::{DbError, query_error};

/// Record that `edge` linked under serving-lease `epoch`, and give its slot:
/// the one the roster holds for it, or — for an edge the roster has not seen —
/// `wanted` when no other edge holds it, otherwise the lowest free one.
/// `None` when every slot is taken.
pub(crate) async fn link_edge(
    pool: &PgPool,
    edge: &str,
    wanted: Option<u16>,
    epoch: i64,
) -> Result<Option<u16>, DbError> {
    let slot: Option<i32> = sqlx::query_scalar(
        "WITH free AS (
             SELECT candidate
             FROM (
                 SELECT $2::integer AS candidate, 0 AS preference
                 UNION ALL
                 SELECT generate_series(1, 16383), 1
             ) AS choices
             WHERE candidate IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM core_edges WHERE slot = candidate)
             ORDER BY preference, candidate
             LIMIT 1
         )
         INSERT INTO core_edges (edge, slot, last_epoch, linked_at)
         SELECT $1, candidate, $3, now() FROM free
         ON CONFLICT (edge) DO UPDATE
             SET last_epoch = EXCLUDED.last_epoch, linked_at = now(), unlinked_at = NULL
         RETURNING slot",
    )
    .bind(edge)
    .bind(wanted.map(i32::from))
    .bind(epoch)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    match slot {
        Some(slot) => Ok(Some(u16::try_from(slot).map_err(|_| {
            DbError::InvalidRoster(format!("core_edges holds slot {slot} for {edge}"))
        })?)),
        // No free slot: the INSERT had no row to insert, and none conflicted.
        None => {
            let existing: Option<i32> =
                sqlx::query_scalar("SELECT slot FROM core_edges WHERE edge = $1")
                    .bind(edge)
                    .fetch_optional(pool)
                    .await
                    .map_err(query_error)?;
            match existing {
                Some(slot) => {
                    sqlx::query(
                        "UPDATE core_edges SET last_epoch = $2, linked_at = now(), \
                         unlinked_at = NULL WHERE edge = $1",
                    )
                    .bind(edge)
                    .bind(epoch)
                    .execute(pool)
                    .await
                    .map_err(query_error)?;
                    Ok(Some(u16::try_from(slot).map_err(|_| {
                        DbError::InvalidRoster(format!("core_edges holds slot {slot} for {edge}"))
                    })?))
                }
                None => Ok(None),
            }
        }
    }
}

/// Record that `edge`'s link ended.
pub(crate) async fn unlink_edge(pool: &PgPool, edge: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE core_edges SET unlinked_at = now() WHERE edge = $1")
        .bind(edge)
        .execute(pool)
        .await
        .map_err(query_error)?;
    Ok(())
}
