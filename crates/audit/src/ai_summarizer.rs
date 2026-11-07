use serde::{Deserialize, Serialize};
use warm_verifier::{FindingSeverity, ForensicReport, VerdictClassification};

/// Structured AI-assisted forensic executive summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiExecutiveSummary {
    pub verdict: String,
    pub verified_facts: Vec<String>,
    pub contextual_inferences: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub human_review_mandatory: bool,
}

pub struct LocalAiSummarizer;

impl LocalAiSummarizer {
    /// Generate an offline advisory summary distinguishing verifiable facts from contextual inferences.
    pub fn summarize(report: &ForensicReport) -> AiExecutiveSummary {
        let mut facts = Vec::new();
        let mut inferences = Vec::new();
        let mut recommendations = Vec::new();

        // 1. Facts directly extracted from verifiable cryptographic evidence
        facts.push(format!(
            "Total audit events verified in SHA-256 hash chain: {}",
            report.total_events
        ));
        facts.push(format!(
            "Hash chain cryptographic integrity status: {}",
            if report.hash_chain_verified {
                "INTACT (No tampering detected)"
            } else {
                "BROKEN / TAMPERED"
            }
        ));

        for finding in &report.findings {
            if finding.severity == FindingSeverity::Critical {
                facts.push(format!(
                    "CRITICAL FINDING: {} (Sequence refs: {:?})",
                    finding.description, finding.supporting_sequences
                ));
            } else if finding.severity == FindingSeverity::Warning {
                facts.push(format!(
                    "WARNING: {} (Sequence refs: {:?})",
                    finding.description, finding.supporting_sequences
                ));
            }
        }

        let compiler_events = report
            .timeline
            .iter()
            .filter(|e| e.category == "Compiler")
            .count();
        if compiler_events > 0 {
            facts.push(format!(
                "Built-in C++ compiler activity recorded: {compiler_events} compilation/execution events in hash chain."
            ));
        } else {
            inferences.push(
                "INFERENCE: No built-in compiler events recorded. Note: Absence of compiler events is not proof that no external compiler was used."
                    .to_string(),
            );
        }

        // 2. Contextual Inferences
        match report.classification {
            VerdictClassification::Safe => {
                inferences.push(
                    "INFERENCE: Participant adhered to contest boundaries during the observed timeline."
                        .to_string(),
                );
                recommendations.push("Approve submission without further inquiry.".to_string());
            }
            VerdictClassification::Unsafe => {
                inferences.push(
                    "INFERENCE: High probability of unauthorized assistance due to active execution of prohibited tooling."
                        .to_string(),
                );
                recommendations.push(
                    "Escalate to Lead Judge for official disqualification review and participant interview."
                        .to_string(),
                );
            }
            VerdictClassification::ReviewRequired => {
                inferences.push(
                    "INFERENCE: Incomplete audit trail indicates either accidental sleep/suspension or intentional termination of client daemon."
                        .to_string(),
                );
                recommendations.push(
                    "Conduct physical proctor inquiry regarding the observed timeline gap."
                        .to_string(),
                );
            }
        }

        AiExecutiveSummary {
            verdict: report.classification.to_string(),
            verified_facts: facts,
            contextual_inferences: inferences,
            recommended_actions: recommendations,
            human_review_mandatory: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_ai_summarizer_distinguishes_facts_and_inferences() {
        let report = ForensicReport {
            contest_uuid: Uuid::new_v4(),
            participant_id: "alice".to_string(),
            session_id: Uuid::new_v4(),
            classification: VerdictClassification::Unsafe,
            summary: "Unsafe".to_string(),
            total_events: 100,
            hash_chain_verified: true,
            findings: vec![warm_verifier::ForensicFinding {
                severity: FindingSeverity::Critical,
                title: "Ollama executed".to_string(),
                description: "ollama.exe was detected".to_string(),
                supporting_sequences: vec![15],
                timestamps: vec!["2026-11-07T10:00:00Z".to_string()],
            }],
            timeline: vec![],
            judge_notes: None,
            authenticated_account_id: None,
            declared_log_name: None,
            participation_mode: warm_core::ParticipationMode::NoAccounts,
        };

        let summary = LocalAiSummarizer::summarize(&report);
        assert_eq!(summary.verdict, "UNSAFE");
        assert!(summary.human_review_mandatory);
        assert!(!summary.verified_facts.is_empty());
        assert!(!summary.contextual_inferences.is_empty());
        assert!(summary
            .verified_facts
            .iter()
            .any(|f| f.contains("CRITICAL")));
    }
}
