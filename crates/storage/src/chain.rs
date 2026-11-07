use uuid::Uuid;
use warm_crypto::{compute_event_hash, compute_genesis_hash};
use warm_events::EventCategory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashChainTracker {
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub current_sequence: u64,
    pub current_hash: String,
}

impl HashChainTracker {
    pub fn new(contest_uuid: Uuid, participant_id: impl Into<String>) -> Self {
        let participant_id = participant_id.into();
        let genesis_hash = compute_genesis_hash(&contest_uuid, &participant_id);
        Self {
            contest_uuid,
            participant_id,
            current_sequence: 0,
            current_hash: genesis_hash,
        }
    }

    pub fn resume(
        contest_uuid: Uuid,
        participant_id: impl Into<String>,
        last_sequence: u64,
        last_hash: impl Into<String>,
    ) -> Self {
        Self {
            contest_uuid,
            participant_id: participant_id.into(),
            current_sequence: last_sequence,
            current_hash: last_hash.into(),
        }
    }

    pub fn step(
        &mut self,
        timestamp_rfc3339: &str,
        category: EventCategory,
        payload_hash: &str,
    ) -> (u64, String, String) {
        let next_seq = self.current_sequence + 1;
        let prev_hash = self.current_hash.clone();
        let new_hash = compute_event_hash(
            next_seq,
            timestamp_rfc3339,
            &prev_hash,
            &category.to_string(),
            payload_hash,
        );

        self.current_sequence = next_seq;
        self.current_hash = new_hash.clone();

        (next_seq, prev_hash, new_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warm_crypto::verify_event_hash;

    #[test]
    fn test_hash_chain_tracker_progression() {
        let contest_uuid = Uuid::new_v4();
        let mut tracker = HashChainTracker::new(contest_uuid, "team-42");

        assert_eq!(tracker.current_sequence, 0);

        let (seq1, prev1, curr1) = tracker.step(
            "2026-11-07T09:00:00Z",
            EventCategory::SystemLifecycle,
            "hash_p1",
        );

        assert_eq!(seq1, 1);
        assert!(verify_event_hash(
            &curr1,
            1,
            "2026-11-07T09:00:00Z",
            &prev1,
            "SystemLifecycle",
            "hash_p1"
        ));

        let (seq2, prev2, curr2) =
            tracker.step("2026-11-07T09:01:00Z", EventCategory::Process, "hash_p2");

        assert_eq!(seq2, 2);
        assert_eq!(prev2, curr1);
        assert!(verify_event_hash(
            &curr2,
            2,
            "2026-11-07T09:01:00Z",
            &prev2,
            "Process",
            "hash_p2"
        ));
    }
}
