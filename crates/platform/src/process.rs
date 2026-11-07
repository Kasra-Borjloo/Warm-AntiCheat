use std::collections::{HashMap, HashSet};
use sysinfo::{ProcessesToUpdate, System};
use warm_events::{ProcessAction, ProcessEventPayload};
use warm_policies::AppPolicy;

/// Information about an observed OS process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedProcess {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub is_prohibited: bool,
}

/// Cross-platform process event collector and policy matcher.
pub struct ProcessCollector {
    system: System,
    policy: AppPolicy,
    known_pids: HashMap<u32, ObservedProcess>,
    simulated_processes: HashSet<String>,
}

impl ProcessCollector {
    pub fn new(policy: AppPolicy) -> Self {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);

        let mut known_pids = HashMap::new();
        for (pid, proc) in system.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc.name().to_string_lossy().to_string();
            let path = proc.exe().map(|p| p.to_string_lossy().to_string());
            let cmdline = Some(
                proc.cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            let is_prohibited = policy.is_prohibited(&name);

            known_pids.insert(
                pid_u32,
                ObservedProcess {
                    pid: pid_u32,
                    name,
                    path,
                    cmdline,
                    is_prohibited,
                },
            );
        }

        Self {
            system,
            policy,
            known_pids,
            simulated_processes: HashSet::new(),
        }
    }

    /// Scan system processes and return newly started or terminated process events.
    pub fn poll_events(&mut self) -> Vec<(ProcessAction, ProcessEventPayload, bool)> {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        let mut events = Vec::new();

        let current_pids: HashMap<u32, (String, Option<String>, Option<String>)> = self
            .system
            .processes()
            .iter()
            .map(|(pid, proc)| {
                (
                    pid.as_u32(),
                    (
                        proc.name().to_string_lossy().to_string(),
                        proc.exe().map(|p| p.to_string_lossy().to_string()),
                        Some(
                            proc.cmd()
                                .iter()
                                .map(|s| s.to_string_lossy().to_string())
                                .collect::<Vec<_>>()
                                .join(" "),
                        ),
                    ),
                )
            })
            .collect();

        // 1. Check for newly spawned processes
        for (&pid, (name, path, cmdline)) in &current_pids {
            if !self.known_pids.contains_key(&pid) {
                let is_prohibited = self.policy.is_prohibited(name);
                let payload = ProcessEventPayload {
                    pid,
                    name: name.clone(),
                    path: path.clone(),
                    cmdline: cmdline.clone(),
                    action: ProcessAction::Started,
                };

                self.known_pids.insert(
                    pid,
                    ObservedProcess {
                        pid,
                        name: name.clone(),
                        path: path.clone(),
                        cmdline: cmdline.clone(),
                        is_prohibited,
                    },
                );

                events.push((ProcessAction::Started, payload, is_prohibited));
            }
        }

        // 2. Check for terminated processes
        let dead_pids: Vec<u32> = self
            .known_pids
            .keys()
            .copied()
            .filter(|pid| !current_pids.contains_key(pid))
            .collect();

        for pid in dead_pids {
            if let Some(proc) = self.known_pids.remove(&pid) {
                let payload = ProcessEventPayload {
                    pid,
                    name: proc.name,
                    path: proc.path,
                    cmdline: proc.cmdline,
                    action: ProcessAction::Terminated,
                };
                events.push((ProcessAction::Terminated, payload, proc.is_prohibited));
            }
        }

        events
    }

    /// Simulate process launch for deterministic tests.
    pub fn simulate_process_launch(
        &mut self,
        name: &str,
        pid: u32,
    ) -> (ProcessAction, ProcessEventPayload, bool) {
        let is_prohibited = self.policy.is_prohibited(name);
        let payload = ProcessEventPayload {
            pid,
            name: name.to_string(),
            path: Some(format!("/usr/bin/{name}")),
            cmdline: Some(format!("{name} --server")),
            action: ProcessAction::Started,
        };
        self.simulated_processes.insert(name.to_string());
        (ProcessAction::Started, payload, is_prohibited)
    }

    /// Return all currently prohibited processes detected on the machine.
    pub fn find_active_prohibited_processes(&self) -> Vec<ObservedProcess> {
        self.known_pids
            .values()
            .filter(|p| p.is_prohibited)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_collector_simulation() {
        let policy = AppPolicy::default();
        let mut collector = ProcessCollector::new(policy);

        // Simulate benign process launch
        let (action, payload, prohibited) = collector.simulate_process_launch("rustc.exe", 9999);
        assert_eq!(action, ProcessAction::Started);
        assert_eq!(payload.name, "rustc.exe");
        assert!(!prohibited);

        // Simulate prohibited AI runtime launch
        let (action_ai, payload_ai, prohibited_ai) =
            collector.simulate_process_launch("ollama.exe", 10001);
        assert_eq!(action_ai, ProcessAction::Started);
        assert_eq!(payload_ai.name, "ollama.exe");
        assert!(prohibited_ai);
    }
}
