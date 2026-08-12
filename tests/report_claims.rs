use std::sync::Arc;

use polarizer::{contract::v2, moderation::ModerationRepository};
use sqlx::{PgPool, Row};
use tokio::sync::Barrier;
use uuid::Uuid;

const CLAIM_LEASE_SECONDS: i64 = 1_800;
const TRANSFER_COOLDOWN_SECONDS: i64 = 300;

fn context(actor_id: &str, request_id: &str) -> v2::RequestContext {
    v2::RequestContext {
        request_id: request_id.to_owned(),
        actor_id: actor_id.to_owned(),
        actor_type: v2::ActorType::Human as i32,
        service_principal: "report-claim-tests".to_owned(),
        idempotency_key: String::new(),
        trace_id: String::new(),
    }
}

async fn insert_pending_report(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO trust_safety.report
         (scope_type, scope_id, reporter_id, subject_type, subject_id, report_type, description, context)
         VALUES ('LOBBY', 'lobby-claim-test', 'reporter-1', 'USER', 'subject-1', 'ABUSE', '', '{}'::jsonb)
         RETURNING id",
    )
    .fetch_one(pool)
    .await?;
    row.try_get("id")
}

fn repository(pool: PgPool) -> ModerationRepository {
    ModerationRepository::new(pool, "report-claim-tests")
}

async fn claim(
    repository: &ModerationRepository,
    actor_id: &str,
    report_id: Uuid,
    expected_version: u64,
) -> anyhow::Result<v2::Report> {
    repository
        .claim_report(
            &context(actor_id, &format!("claim-{actor_id}-{}", Uuid::now_v7())),
            report_id,
            expected_version as i64,
            CLAIM_LEASE_SECONDS,
            TRANSFER_COOLDOWN_SECONDS,
            false,
        )
        .await
}

async fn unclaim(
    repository: &ModerationRepository,
    actor_id: &str,
    report_id: Uuid,
    expected_version: u64,
) -> anyhow::Result<v2::Report> {
    repository
        .unclaim_report(
            &context(actor_id, &format!("unclaim-{actor_id}-{}", Uuid::now_v7())),
            report_id,
            expected_version as i64,
        )
        .await
}

#[sqlx::test]
async fn voluntary_unclaim_clears_cooldown_and_allows_either_staff_member(
    pool: PgPool,
) -> anyhow::Result<()> {
    let report_id = insert_pending_report(&pool).await?;
    let repository = repository(pool.clone());

    let initial = repository.get_report(report_id).await?;
    let claimed = claim(&repository, "staff-a", report_id, initial.version).await?;
    let released = unclaim(&repository, "staff-a", report_id, claimed.version).await?;

    assert!(released.claimed_by.is_empty());
    assert!(released.claimed_at.is_none());
    assert!(released.claim_expires_at.is_none());
    assert!(released.last_claim_change_at.is_none());

    let reclaimed_by_a = claim(&repository, "staff-a", report_id, released.version).await?;
    assert_eq!(reclaimed_by_a.claimed_by, "staff-a");

    let released_again = unclaim(&repository, "staff-a", report_id, reclaimed_by_a.version).await?;
    let reclaimed_by_b = claim(&repository, "staff-b", report_id, released_again.version).await?;
    assert_eq!(reclaimed_by_b.claimed_by, "staff-b");

    let audit = sqlx::query(
        "SELECT action, actor_id FROM trust_safety.audit_log
         WHERE resource_type = 'REPORT' AND resource_id = $1
         ORDER BY created_at, id",
    )
    .bind(report_id.to_string())
    .fetch_all(&pool)
    .await?;
    let transitions = audit
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("action")?,
                row.try_get::<String, _>("actor_id")?,
            ))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    assert_eq!(
        transitions,
        vec![
            ("CLAIM_REPORT".to_owned(), "staff-a".to_owned()),
            ("UNCLAIM_REPORT".to_owned(), "staff-a".to_owned()),
            ("CLAIM_REPORT".to_owned(), "staff-a".to_owned()),
            ("UNCLAIM_REPORT".to_owned(), "staff-a".to_owned()),
            ("CLAIM_REPORT".to_owned(), "staff-b".to_owned()),
        ]
    );

    Ok(())
}

#[sqlx::test]
async fn live_claim_rejects_ordinary_takeover_and_transfer_cooldown_is_preserved(
    pool: PgPool,
) -> anyhow::Result<()> {
    let report_id = insert_pending_report(&pool).await?;
    let repository = repository(pool);
    let initial = repository.get_report(report_id).await?;
    let claimed = claim(&repository, "staff-a", report_id, initial.version).await?;

    let ordinary_takeover = claim(&repository, "staff-b", report_id, claimed.version)
        .await
        .expect_err("a live claim must not be overwritten by ordinary claim");
    assert!(ordinary_takeover.to_string().contains("conflict"));
    assert_eq!(
        repository.get_report(report_id).await?.claimed_by,
        "staff-a"
    );

    let transfer = repository
        .transfer_report(
            &context("admin-1", &format!("transfer-{}", Uuid::now_v7())),
            report_id,
            "staff-b",
            claimed.version as i64,
            CLAIM_LEASE_SECONDS,
            TRANSFER_COOLDOWN_SECONDS,
            false,
            false,
        )
        .await
        .expect_err("a non-bypassed transfer must retain its cooldown");
    assert!(transfer.to_string().contains("conflict"));

    let transferred = repository
        .transfer_report(
            &context("admin-1", &format!("transfer-{}", Uuid::now_v7())),
            report_id,
            "staff-b",
            claimed.version as i64,
            CLAIM_LEASE_SECONDS,
            TRANSFER_COOLDOWN_SECONDS,
            false,
            true,
        )
        .await?;
    assert_eq!(transferred.claimed_by, "staff-b");

    Ok(())
}

#[sqlx::test]
async fn concurrent_claims_have_one_atomic_winner_and_one_conflict(
    pool: PgPool,
) -> anyhow::Result<()> {
    let report_id = insert_pending_report(&pool).await?;
    let repository = repository(pool.clone());
    let initial = repository.get_report(report_id).await?;
    let barrier = Arc::new(Barrier::new(3));

    let staff_a_repository = repository.clone();
    let staff_a_barrier = Arc::clone(&barrier);
    let staff_a = tokio::spawn(async move {
        staff_a_barrier.wait().await;
        claim(&staff_a_repository, "staff-a", report_id, initial.version).await
    });

    let staff_b_repository = repository.clone();
    let staff_b_barrier = Arc::clone(&barrier);
    let staff_b = tokio::spawn(async move {
        staff_b_barrier.wait().await;
        claim(&staff_b_repository, "staff-b", report_id, initial.version).await
    });

    barrier.wait().await;
    let staff_a_result = staff_a.await?;
    let staff_b_result = staff_b.await?;
    assert_ne!(staff_a_result.is_ok(), staff_b_result.is_ok());

    let stored = repository.get_report(report_id).await?;
    let winner = if staff_a_result.is_ok() {
        "staff-a"
    } else {
        "staff-b"
    };
    assert_eq!(stored.claimed_by, winner);

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM trust_safety.audit_log
         WHERE action = 'CLAIM_REPORT' AND resource_type = 'REPORT' AND resource_id = $1",
    )
    .bind(report_id.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(audit_count, 1);

    Ok(())
}
