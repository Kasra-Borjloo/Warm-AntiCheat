use std::collections::BTreeMap;
use std::time::Instant;
use warm_verifier::ForensicReport;

/// Deterministic audit statistics and performance metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditStats {
    pub total_events: u64,
    pub processing_time_ms: u128,
    pub event_distribution: BTreeMap<String, u64>,
    pub critical_findings_count: usize,
    pub warning_findings_count: usize,
}

pub struct DeterministicAuditEngine;

impl DeterministicAuditEngine {
    /// Analyze an existing forensic report and compute metrics and timing.
    pub fn compute_stats(report: &ForensicReport) -> AuditStats {
        let start = Instant::now();
        let mut distribution = BTreeMap::new();

        for event in &report.timeline {
            *distribution.entry(event.category.clone()).or_insert(0) += 1;
        }

        let elapsed = start.elapsed().as_millis();
        let critical = report
            .findings
            .iter()
            .filter(|f| f.severity == warm_verifier::FindingSeverity::Critical)
            .count();
        let warning = report
            .findings
            .iter()
            .filter(|f| f.severity == warm_verifier::FindingSeverity::Warning)
            .count();

        AuditStats {
            total_events: report.total_events,
            processing_time_ms: elapsed,
            event_distribution: distribution,
            critical_findings_count: critical,
            warning_findings_count: warning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use warm_verifier::{ForensicReport, VerdictClassification};

    #[test]
    fn test_deterministic_audit_stats() {
        let report = ForensicReport {
            contest_uuid: Uuid::new_v4(),
            participant_id: "test".to_string(),
            session_id: Uuid::new_v4(),
            classification: VerdictClassification::Safe,
            summary: "Clean".to_string(),
            total_events: 10,
            hash_chain_verified: true,
            findings: vec![],
            timeline: vec![],
            judge_notes: None,
        };

        let stats = DeterministicAuditEngine::compute_stats(&report);
        assert_eq!(stats.total_events, 10);
        assert_eq!(stats.critical_findings_count, 0);
    }
}
