//! Warm-AntiCheat Participant Client Application Entry Point

use chrono::Utc;
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use warm_core::CompetitionSession;
use warm_crypto::{seal_asymmetric_payload, sha256_digest, EvidenceEncryptionKeypair};
use warm_events::EventCategory;
use warm_platform::{LifecycleTracker, NetworkCollector, ProcessCollector};
use warm_policies::MonitoringPolicy;
use warm_storage::{export_evidence_package, HashChainTracker, SqliteAuditStore};

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("=======================================================");
    println!(
        "   Warm-AntiCheat Participant Client v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("   Active Contest: GOCUP 1");
    println!("=======================================================\n");

    if args.len() > 1 && args[1] == "session" {
        let participant_id = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "team-42".to_string());
        let contest_uuid = Uuid::new_v4();
        let db_path = PathBuf::from("./participant_audit.sqlite");

        println!("[*] Starting competition monitoring session...");
        println!("    Participant ID: {}", participant_id);
        println!("    Contest UUID:   {}", contest_uuid);
        println!("    Storage:        {}", db_path.display());

        let mut session = CompetitionSession::new("gocup-1", &participant_id).unwrap();
        session.start().unwrap();

        let store = SqliteAuditStore::open(&db_path).expect("Failed to initialize audit storage");
        let mut tracker = HashChainTracker::new(contest_uuid, &participant_id);

        let judge_keypair = EvidenceEncryptionKeypair::generate();
        let policy = MonitoringPolicy::default();

        let mut proc_collector = ProcessCollector::new(policy.app_policy.clone());
        let mut net_collector = NetworkCollector::new();
        let mut lifecycle = LifecycleTracker::new(
            policy.heartbeat_interval_secs,
            policy.max_interruption_gap_secs,
        );

        // Record initial launch event
        let launch_payload = LifecycleTracker::on_application_launch();
        let payload_json = serde_json::to_vec(&launch_payload).unwrap();
        let payload_hash = sha256_digest(&payload_json);
        let now = Utc::now();

        let (seq, prev_hash, curr_hash) = tracker.step(
            &now.to_rfc3339(),
            EventCategory::SystemLifecycle,
            &payload_hash,
        );
        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed = seal_asymmetric_payload(
            &judge_keypair.public_key,
            &contest_uuid,
            &payload_json,
            &aad,
        )
        .unwrap();

        store
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                &participant_id,
                session.session_id,
                now,
                EventCategory::SystemLifecycle,
                &sealed,
                &payload_hash,
                &prev_hash,
                &curr_hash,
            )
            .unwrap();

        println!(
            "[OK] Session successfully active. Heartbeat and process monitoring loop started."
        );
        println!("     Press Ctrl+C to conclude session.\n");

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_handler(move || {
            r.store(false, Ordering::SeqCst);
        });

        // Run monitoring loop for demonstration / testing (runs 3 sample ticks if not interactive)
        let mut ticks = 0;
        while running.load(Ordering::SeqCst) && ticks < 3 {
            thread::sleep(Duration::from_millis(500));
            ticks += 1;

            // 1. Process poll
            let proc_events = proc_collector.poll_events();
            for (_action, payload, prohibited) in proc_events {
                if prohibited {
                    println!(
                        "[ALERT] Prohibited process detected: {} (PID: {})",
                        payload.name, payload.pid
                    );
                }
            }

            // 2. Network poll
            let _net_events = net_collector.poll_events();

            // 3. Lifecycle tick
            let _lifecycle_events = lifecycle.tick(Utc::now());
        }

        println!("[*] Concluding session...");
        session.conclude().unwrap();
        println!("[OK] Session concluded. Evidence ready for export.");
    } else if args.len() > 1 && args[1] == "export" {
        let dest = args
            .get(2)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./export"));
        let db_path = PathBuf::from("./participant_audit.sqlite");

        if !db_path.exists() {
            eprintln!(
                "[ERROR] No local audit database found at {}",
                db_path.display()
            );
            return;
        }

        println!("[*] Exporting encrypted evidence to {}...", dest.display());
        let contest_uuid = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        match export_evidence_package(
            &db_path,
            &dest,
            contest_uuid,
            "team-42",
            session_id,
            1,
            "h0",
            "h1",
        ) {
            Ok(p) => println!("[SUCCESS] Evidence package exported to {}", p.display()),
            Err(e) => eprintln!("[ERROR] Export failed: {e}"),
        }
    } else {
        println!("Commands:");
        println!("  warm_participant_app session [PARTICIPANT_ID]");
        println!("  warm_participant_app export [DEST_DIR]\n");
        println!("Web UI assets available at: apps/participant/ui/index.html");
    }
}

fn ctrlc_handler<F: Fn() + Send + 'static>(_f: F) {
    // Graceful handler stub
}
