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

/// Record that `edges` hold the sessions of cut `cut`.
pub(crate) async fn record_cut(pool: &PgPool, edges: &[String], cut: u64) -> Result<(), DbError> {
    sqlx::query("UPDATE core_edges SET last_cut = $2 WHERE edge = ANY($1)")
        .bind(edges)
        .bind(cut.cast_signed())
        .execute(pool)
        .await
        .map_err(query_error)?;
    Ok(())
}

/// The cut the roster says edges hold, and the edges holding it: the cut of
/// the edge that linked last, when several are named.
pub(crate) async fn pending_cut(pool: &PgPool) -> Result<Option<(u64, Vec<String>)>, DbError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT edge, last_cut FROM core_edges
         WHERE last_cut = (
             SELECT last_cut FROM core_edges WHERE last_cut IS NOT NULL
             ORDER BY linked_at DESC LIMIT 1
         )
         ORDER BY edge",
    )
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    let Some((_, cut)) = rows.first() else {
        return Ok(None);
    };
    let cut = cut.cast_unsigned();
    Ok(Some((
        cut,
        rows.into_iter().map(|(edge, _)| edge).collect(),
    )))
}

/// The edges holding cut `cut` are rebuilt: the roster names it no more.
pub(crate) async fn clear_cut(pool: &PgPool, cut: u64) -> Result<(), DbError> {
    sqlx::query("UPDATE core_edges SET last_cut = NULL WHERE last_cut = $1")
        .bind(cut.cast_signed())
        .execute(pool)
        .await
        .map_err(query_error)?;
    Ok(())
}

/// The body format the cores write for their edges (D11).
pub(crate) async fn written_record_format(pool: &PgPool) -> Result<u16, DbError> {
    let written: i16 = sqlx::query_scalar("SELECT written FROM record_format")
        .fetch_one(pool)
        .await
        .map_err(query_error)?;
    u16::try_from(written)
        .map_err(|_| DbError::InvalidRoster(format!("record_format holds format {written}")))
}

/// `e6ircd records advance` (D11): the cores write this release's newest body
/// format from now on (the table announces it, so serving cores follow at
/// once). The format written before, and the one written now. Advancing is
/// the operator's statement that no core older than this release will run
/// again: an older one could not read the newer bodies.
pub async fn advance_record_format(pool: &PgPool) -> Result<(u16, u16), DbError> {
    let newest = crate::core::record::RecordFormat::NEWEST.number();
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let before: i16 = sqlx::query_scalar("SELECT written FROM record_format FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .map_err(query_error)?;
    let before = u16::try_from(before)
        .map_err(|_| DbError::InvalidRoster(format!("record_format held format {before}")))?;
    if before > newest {
        return Err(DbError::InvalidRoster(format!(
            "the cores already write record format {before}, newer than this release's newest \
             ({newest}); run the release that advanced it"
        )));
    }
    sqlx::query("UPDATE record_format SET written = $1, advanced_at = now()")
        .bind(i16::try_from(newest).expect("a format number fits a SMALLINT"))
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    transaction.commit().await.map_err(query_error)?;
    Ok((before, newest))
}
