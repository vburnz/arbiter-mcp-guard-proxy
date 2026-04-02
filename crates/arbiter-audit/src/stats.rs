//! In-memory audit statistics tracker.
//!
//! Maintains lightweight per-session counters for denied requests and
//! anomaly detections. Updated on each audit entry write. Queryable
//! by session ID for session close summaries.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Per-session audit statistics.
#[derive(Debug, Default)]
struct SessionCounters {
    denied: AtomicU64,
    anomalies: AtomicU64,
}

/// Queryable audit statistics returned to callers.
#[derive(Debug, Clone, Default)]
pub struct SessionAuditStats {
    pub denied_count: u64,
    pub anomaly_count: u64,
}

/// Aggregated audit statistics across all tracked sessions.
#[derive(Debug, Clone, Default)]
pub struct AggregateAuditStats {
    pub total_denied: u64,
    pub total_anomalies: u64,
    pub sessions_with_anomalies: u64,
    pub sessions_with_denials: u64,
    /// Per-session stats keyed by session ID.
    pub per_session: Vec<(String, SessionAuditStats)>,
}

/// Thread-safe audit stats tracker, shared between the audit write path
/// and the session close query path.
#[derive(Clone, Default)]
pub struct AuditStats {
    sessions: Arc<RwLock<HashMap<String, Arc<SessionCounters>>>>,
}

impl AuditStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an audit entry. Inspects the entry to update per-session counters.
    pub async fn record(&self, entry: &crate::entry::AuditEntry) {
        if entry.task_session_id.is_empty() {
            return;
        }

        let counters = {
            let sessions = self.sessions.read().await;
            sessions.get(&entry.task_session_id).cloned()
        };

        let counters = match counters {
            Some(c) => c,
            None => {
                let mut sessions = self.sessions.write().await;
                sessions
                    .entry(entry.task_session_id.clone())
                    .or_insert_with(|| Arc::new(SessionCounters::default()))
                    .clone()
            }
        };

        if entry.authorization_decision == "deny" {
            counters.denied.fetch_add(1, Ordering::Relaxed);
        }

        if !entry.anomaly_flags.is_empty() {
            counters.anomalies.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Query stats for a specific session.
    pub async fn stats_for_session(&self, session_id: &str) -> SessionAuditStats {
        let sessions = self.sessions.read().await;
        match sessions.get(session_id) {
            Some(counters) => SessionAuditStats {
                denied_count: counters.denied.load(Ordering::Relaxed),
                anomaly_count: counters.anomalies.load(Ordering::Relaxed),
            },
            None => SessionAuditStats::default(),
        }
    }

    /// Remove stats for a session (called after session close to prevent unbounded growth).
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Aggregate stats across all tracked sessions. Returns totals and counts
    /// of sessions that have anomalies or denials.
    pub async fn aggregate(&self) -> AggregateAuditStats {
        let sessions = self.sessions.read().await;
        let mut total_denied: u64 = 0;
        let mut total_anomalies: u64 = 0;
        let mut sessions_with_anomalies: u64 = 0;
        let mut sessions_with_denials: u64 = 0;
        let mut per_session = Vec::with_capacity(sessions.len());

        for (session_id, counters) in sessions.iter() {
            let denied = counters.denied.load(Ordering::Relaxed);
            let anomalies = counters.anomalies.load(Ordering::Relaxed);
            total_denied += denied;
            total_anomalies += anomalies;
            if anomalies > 0 {
                sessions_with_anomalies += 1;
            }
            if denied > 0 {
                sessions_with_denials += 1;
            }
            per_session.push((
                session_id.clone(),
                SessionAuditStats {
                    denied_count: denied,
                    anomaly_count: anomalies,
                },
            ));
        }

        AggregateAuditStats {
            total_denied,
            total_anomalies,
            sessions_with_anomalies,
            sessions_with_denials,
            per_session,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::AuditEntry;
    use uuid::Uuid;

    #[tokio::test]
    async fn tracks_denied_and_anomalies() {
        let stats = AuditStats::new();
        let session_id = Uuid::new_v4().to_string();

        // Allowed request, no counters increment.
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.task_session_id = session_id.clone();
        entry.authorization_decision = "allow".into();
        stats.record(&entry).await;

        // Denied request.
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.task_session_id = session_id.clone();
        entry.authorization_decision = "deny".into();
        stats.record(&entry).await;

        // Another denied request with anomaly flag.
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.task_session_id = session_id.clone();
        entry.authorization_decision = "deny".into();
        entry.anomaly_flags = vec!["suspicious".into()];
        stats.record(&entry).await;

        let result = stats.stats_for_session(&session_id).await;
        assert_eq!(result.denied_count, 2);
        assert_eq!(result.anomaly_count, 1);
    }

    #[tokio::test]
    async fn unknown_session_returns_zero() {
        let stats = AuditStats::new();
        let result = stats.stats_for_session("nonexistent").await;
        assert_eq!(result.denied_count, 0);
        assert_eq!(result.anomaly_count, 0);
    }

    #[tokio::test]
    async fn remove_session_cleans_up() {
        let stats = AuditStats::new();
        let session_id = Uuid::new_v4().to_string();

        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.task_session_id = session_id.clone();
        entry.authorization_decision = "deny".into();
        stats.record(&entry).await;

        stats.remove_session(&session_id).await;
        let result = stats.stats_for_session(&session_id).await;
        assert_eq!(result.denied_count, 0);
    }

    // -----------------------------------------------------------------------
    // Unbounded memory growth in audit stats map
    // -----------------------------------------------------------------------

    /// Create 1000 unique session IDs and record entries for each. Verify
    /// that aggregate() returns correct totals. This documents the growth
    /// behavior: without remove_session(), the map grows monotonically.
    /// Also verify that remove_session() can reclaim entries.
    #[tokio::test]
    async fn stats_growth_with_many_sessions() {
        let stats = AuditStats::new();
        let session_count = 1000;

        let mut session_ids = Vec::with_capacity(session_count);
        for i in 0..session_count {
            let session_id = format!("session-{}", i);
            session_ids.push(session_id.clone());

            let mut entry = AuditEntry::new(Uuid::new_v4());
            entry.task_session_id = session_id;
            entry.authorization_decision = "deny".into();
            entry.anomaly_flags = if i % 3 == 0 {
                vec!["anomaly".into()]
            } else {
                vec![]
            };
            stats.record(&entry).await;
        }

        // Verify aggregate returns correct totals.
        let agg = stats.aggregate().await;
        assert_eq!(
            agg.per_session.len(),
            session_count,
            "all {} sessions must be tracked",
            session_count
        );
        assert_eq!(
            agg.total_denied, session_count as u64,
            "every session had one denied entry"
        );
        assert_eq!(
            agg.sessions_with_denials, session_count as u64,
            "all sessions have denials"
        );
        // Every 3rd session (i % 3 == 0) has an anomaly: 0, 3, 6, ..., 999
        // That's ceil(1000/3) = 334 sessions.
        let expected_anomaly_sessions = (0..session_count).filter(|i| i % 3 == 0).count() as u64;
        assert_eq!(
            agg.sessions_with_anomalies, expected_anomaly_sessions,
            "every 3rd session should have anomaly flag"
        );
        assert_eq!(
            agg.total_anomalies, expected_anomaly_sessions,
            "one anomaly entry per anomaly session"
        );

        // Verify that removing sessions reduces the map size.
        for session_id in &session_ids[..500] {
            stats.remove_session(session_id).await;
        }
        let agg_after = stats.aggregate().await;
        assert_eq!(
            agg_after.per_session.len(),
            500,
            "after removing 500 sessions, 500 must remain"
        );
    }
}
