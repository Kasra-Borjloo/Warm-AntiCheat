//! Security policy configuration and rule definitions.

pub mod apps;
pub mod browser;

pub use apps::*;
pub use browser::*;

use serde::{Deserialize, Serialize};

/// Comprehensive competition monitoring policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitoringPolicy {
    pub app_policy: AppPolicy,
    pub browser_policy: BrowserPolicy,
    pub heartbeat_interval_secs: u64,
    pub max_interruption_gap_secs: u64,
    pub retention_days: u32,
}

impl Default for MonitoringPolicy {
    fn default() -> Self {
        Self {
            app_policy: AppPolicy::default(),
            browser_policy: BrowserPolicy::default(),
            heartbeat_interval_secs: 15,
            max_interruption_gap_secs: 60,
            retention_days: 30,
        }
    }
}
