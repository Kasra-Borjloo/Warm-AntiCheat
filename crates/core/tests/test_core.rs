use chrono::{Duration, Utc};
use warm_core::*;

#[test]
fn test_full_core_integration_workflow() {
    let start = Utc::now();
    let end = start + Duration::hours(4);
    let contest = Contest::with_times(
        "GOCUP 1",
        "National Computing Society",
        "Official Algorithmic Contest",
        Some(start),
        Some(end),
    )
    .expect("Contest should be created");

    assert_eq!(contest.title, "GOCUP 1");
    assert_eq!(contest.id, "gocup-1");
    assert!(contest.validate().is_ok());

    let participant = Participant::new("user-42", &contest.id, "Alice")
        .expect("Participant should be created")
        .with_email_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    assert_eq!(participant.id, "user-42");
    assert_eq!(participant.contest_id, "gocup-1");
    assert!(participant.validate().is_ok());

    let token = EnrollmentToken::new(
        &contest.id,
        &participant.id,
        "SECRET_ENROLL_TOKEN_123",
        "dummy_signature_hex",
    )
    .expect("Token should be created");

    assert_eq!(
        token.signing_bytes(),
        b"gocup-1:user-42:SECRET_ENROLL_TOKEN_123".to_vec()
    );

    let mut session =
        CompetitionSession::new(&contest.id, &participant.id).expect("Session should initialize");

    assert_eq!(session.state, SessionState::Initialized);
    assert!(session.end_time.is_none());

    session.start().expect("Session should start");
    assert_eq!(session.state, SessionState::Active);

    session.pause().expect("Session should pause");
    assert_eq!(session.state, SessionState::Paused);

    session.resume().expect("Session should resume");
    assert_eq!(session.state, SessionState::Active);

    session.conclude().expect("Session should conclude");
    assert_eq!(session.state, SessionState::Concluded);
    assert!(session.end_time.is_some());

    session.submit().expect("Session should submit");
    assert_eq!(session.state, SessionState::Submitted);
}

#[test]
fn test_core_serialization_roundtrip() {
    let start = Utc::now();
    let end = start + Duration::hours(2);
    let contest =
        Contest::with_times("Roundtrip Test", "Org", "Desc", Some(start), Some(end)).unwrap();

    let json = serde_json::to_string(&contest).expect("Should serialize");
    let deserialized: Contest = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(contest, deserialized);
}
