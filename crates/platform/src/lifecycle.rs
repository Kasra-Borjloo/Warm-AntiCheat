use chrono::{DateTime, Utc};
use warm_events::{LifecycleEventPayload, LifecycleEventType};

pub struct LifecycleTracker {
    pub last_heartbeat: DateTime<Utc>,
    pub heartbeat_interval_secs: u64,
    pub max_gap_secs: u64,
}

impl LifecycleTracker {
    pub fn new(heartbeat_interval_secs: u64, max_gap_secs: u64) -> Self {
        Self {
            last_heartbeat: Utc::now(),
            heartbeat_interval_secs,
            max_gap_secs,
        }
    }

    /// Emits application startup event payload.
    pub fn on_application_launch() -> LifecycleEventPayload {
        LifecycleEventPayload {
            event_type: LifecycleEventType::ApplicationLaunch,
            details: Some(format!(
                "Warm-AntiCheat Client Started on {}",
                std::env::consts::OS
            )),
        }
    }

    /// Emits clean application exit payload.
    pub fn on_application_exit() -> LifecycleEventPayload {
        LifecycleEventPayload {
            event_type: LifecycleEventType::ApplicationExit,
            details: Some("Client cleanly stopped by user or proctor".to_string()),
        }
    }

    /// Perform a heartbeat tick check. If wall-clock elapsed time significantly exceeds interval,
    /// emits sleep / interruption event, otherwise emits standard heartbeat.
    pub fn tick(&mut self, current_time: DateTime<Utc>) -> Vec<LifecycleEventPayload> {
        let mut events = Vec::new();
        let elapsed_secs = (current_time - self.last_heartbeat).num_seconds();

        if elapsed_secs < 0 {
            // Negative time jump: clock tampering or rollback
            events.push(LifecycleEventPayload {
                event_type: LifecycleEventType::MonitoringInterrupted,
                details: Some(format!(
                    "System clock rolled backwards by {}s",
                    elapsed_secs.abs()
                )),
            });
        } else if elapsed_secs as u64 > self.max_gap_secs {
            // Significant gap detected: device slept, froze, or monitoring process was suspended
            events.push(LifecycleEventPayload {
                event_type: LifecycleEventType::SleepDetected,
                details: Some(format!(
                    "Elapsed time gap between heartbeats: {}s",
                    elapsed_secs
                )),
            });
            events.push(LifecycleEventPayload {
                event_type: LifecycleEventType::WakeDetected,
                details: Some("Monitoring resumed after sleep/interruption".to_string()),
            });
        }

        events.push(LifecycleEventPayload {
            event_type: LifecycleEventType::Heartbeat,
            details: Some(format!("Heartbeat tick at {}", current_time.to_rfc3339())),
        });

        self.last_heartbeat = current_time;
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_lifecycle_normal_heartbeat() {
        let mut tracker = LifecycleTracker::new(15, 60);
        let t1 = tracker.last_heartbeat + Duration::seconds(15);
        let events = tracker.tick(t1);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, LifecycleEventType::Heartbeat);
    }

    #[test]
    fn test_lifecycle_sleep_detection() {
        let mut tracker = LifecycleTracker::new(15, 60);
        // Advance time by 300 seconds (5 minutes gap = sleep)
        let t_wake = tracker.last_heartbeat + Duration::seconds(300);
        let events = tracker.tick(t_wake);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, LifecycleEventType::SleepDetected);
        assert_eq!(events[1].event_type, LifecycleEventType::WakeDetected);
        assert_eq!(events[2].event_type, LifecycleEventType::Heartbeat);
    }

    #[test]
    fn test_lifecycle_clock_rollback() {
        let mut tracker = LifecycleTracker::new(15, 60);
        // Roll time backwards by 60 seconds
        let t_rollback = tracker.last_heartbeat - Duration::seconds(60);
        let events = tracker.tick(t_rollback);

        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].event_type,
            LifecycleEventType::MonitoringInterrupted
        );
        assert_eq!(events[1].event_type, LifecycleEventType::Heartbeat);
    }
}
