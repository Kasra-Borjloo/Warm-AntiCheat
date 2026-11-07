use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use warm_events::{ProcessAction, ProcessEventPayload};
use warm_policies::AppPolicy;

type ProcessSample = (String, Option<String>, Option<String>, f32, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedProcess {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub is_prohibited: bool,
}

pub fn is_self_or_system(name: &str) -> bool {
    let lower = name.trim().to_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    matches!(
        base,
        "warm_participant_app"
            | "warm-anticheat-participant"
            | "warm-anticheat"
            | "warm-participant"
            | "warm_judge_app"
            | "warm_builder_app"
            | "warm-contest-maker"
            | "system"
            | "system idle process"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "svchost"
            | "fontdrvhost"
            | "dwm"
            | "explorer"
            | "sihost"
            | "taskhostw"
            | "conhost"
            | "runtimebroker"
            | "searchindexer"
            | "searchhost"
            | "startmenuexperiencehost"
            | "shellexperiencehost"
            | "textinputhost"
            | "ctfmon"
            | "spoolsv"
            | "smartscreen"
            | "securityhealthservice"
            | "mpcmdrun"
            | "msmpeng"
            | "audiodg"
            | "init"
            | "systemd"
            | "dbus-daemon"
            | "launchd"
            | "windowserver"
            | "kernel_task"
    )
}

pub fn is_whitelisted_process(name: &str) -> bool {
    if is_self_or_system(name) {
        return true;
    }
    let lower = name.trim().to_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    matches!(
        base,
        "code"
            | "devenv"
            | "clion64"
            | "clion"
            | "pycharm64"
            | "idea64"
            | "sublime_text"
            | "notepad++"
            | "notepad"
            | "gedit"
            | "kate"
            | "vim"
            | "nvim"
            | "emacs"
            | "g++"
            | "gcc"
            | "gdb"
            | "lldb"
            | "make"
            | "ninja"
            | "rustc"
            | "cargo"
            | "msedge"
            | "chrome"
            | "firefox"
            | "brave"
            | "safari"
            | "opera"
    )
}

pub struct ProcessCollector {
    system: System,
    policy: AppPolicy,
    known_pids: HashMap<u32, ObservedProcess>,
    simulated_processes: HashSet<String>,
    pending_initial_events: Vec<(ProcessAction, ProcessEventPayload, bool)>,
    reported_ports: HashSet<u16>,
}

impl ProcessCollector {
    pub fn new(policy: AppPolicy) -> Self {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);

        let mut known_pids = HashMap::new();
        let mut pending_initial_events = Vec::new();

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

            let cpu = proc.cpu_usage();
            let mem = proc.memory();
            let is_whitelisted = is_whitelisted_process(&name);
            let is_anomalous_resource = !is_whitelisted && (cpu > 75.0 || mem > 2_147_483_648);
            let is_prohibited = if is_self_or_system(&name) {
                false
            } else {
                policy.is_prohibited(&name)
                    || is_anomalous_resource
                    || cmdline
                        .as_deref()
                        .and_then(AppPolicy::inspect_command_line)
                        .is_some()
            };

            if is_prohibited {
                pending_initial_events.push((
                    ProcessAction::Started,
                    ProcessEventPayload {
                        pid: pid_u32,
                        name: name.clone(),
                        path: path.clone(),
                        cmdline: cmdline.clone(),
                        action: ProcessAction::Started,
                        screenshot_attachment: None,
                        listening_ports: Vec::new(),
                        cpu_usage: Some(cpu),
                        memory_bytes: Some(mem),
                        is_anomalous_resource,
                        contest_relative_time: None,
                    },
                    true,
                ));
            }

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

        let mut reported_ports = HashSet::new();
        let active_ports = Self::scan_active_ai_ports();
        for (port, desc) in active_ports {
            reported_ports.insert(port);
            pending_initial_events.push((
                ProcessAction::Started,
                ProcessEventPayload {
                    pid: 0,
                    name: format!("Local AI Server: {desc}"),
                    path: None,
                    cmdline: Some(format!("127.0.0.1:{port}")),
                    action: ProcessAction::Started,
                    screenshot_attachment: None,
                    listening_ports: vec![port],
                    cpu_usage: None,
                    memory_bytes: None,
                    is_anomalous_resource: true,
                    contest_relative_time: None,
                },
                true,
            ));
        }

        Self {
            system,
            policy,
            known_pids,
            simulated_processes: HashSet::new(),
            pending_initial_events,
            reported_ports,
        }
    }

    pub fn poll_events(&mut self) -> Vec<(ProcessAction, ProcessEventPayload, bool)> {
        let mut events = Vec::new();

        if !self.pending_initial_events.is_empty() {
            events.append(&mut self.pending_initial_events);
        }

        self.system.refresh_processes(ProcessesToUpdate::All, true);

        let current_pids: HashMap<u32, ProcessSample> = self
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
                        proc.cpu_usage(),
                        proc.memory(),
                    ),
                )
            })
            .collect();

        for (&pid, (name, path, cmdline, cpu, mem)) in &current_pids {
            if !self.known_pids.contains_key(&pid) {
                let is_whitelisted = is_whitelisted_process(name);
                let is_anomalous_resource =
                    !is_whitelisted && (*cpu > 75.0 || *mem > 2_147_483_648);
                let is_prohibited = if is_self_or_system(name) {
                    false
                } else {
                    self.policy.is_prohibited(name)
                        || is_anomalous_resource
                        || cmdline
                            .as_deref()
                            .and_then(AppPolicy::inspect_command_line)
                            .is_some()
                };

                let payload = ProcessEventPayload {
                    pid,
                    name: name.clone(),
                    path: path.clone(),
                    cmdline: cmdline.clone(),
                    action: ProcessAction::Started,
                    screenshot_attachment: None,
                    listening_ports: Vec::new(),
                    cpu_usage: Some(*cpu),
                    memory_bytes: Some(*mem),
                    is_anomalous_resource,
                    contest_relative_time: None,
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
                    screenshot_attachment: None,
                    listening_ports: Vec::new(),
                    cpu_usage: None,
                    memory_bytes: None,
                    is_anomalous_resource: false,
                    contest_relative_time: None,
                };
                events.push((ProcessAction::Terminated, payload, proc.is_prohibited));
            }
        }

        let current_ports = Self::scan_active_ai_ports();
        for (port, desc) in current_ports {
            if !self.reported_ports.contains(&port) {
                self.reported_ports.insert(port);
                events.push((
                    ProcessAction::Started,
                    ProcessEventPayload {
                        pid: 0,
                        name: format!("Local AI Server: {desc}"),
                        path: None,
                        cmdline: Some(format!("127.0.0.1:{port}")),
                        action: ProcessAction::Started,
                        screenshot_attachment: None,
                        listening_ports: vec![port],
                        cpu_usage: None,
                        memory_bytes: None,
                        is_anomalous_resource: false,
                        contest_relative_time: None,
                    },
                    true,
                ));
            }
        }

        events
    }

    pub fn scan_active_ai_ports() -> Vec<(u16, &'static str)> {
        let targets = [
            (11434, "Ollama Local AI Inference Runtime"),
            (1234, "LM Studio Local LLM Server"),
            (8080, "llama.cpp / Local LLM Server"),
            (7860, "Local AI WebUI / Gradio Server"),
            (5000, "Text-Generation-WebUI API Server"),
            (8000, "vLLM / High-Throughput Inference Server"),
            (8888, "Jupyter Notebook Server"),
        ];

        let mut active = Vec::new();
        for (port, desc) in targets {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            if TcpStream::connect_timeout(&addr, Duration::from_millis(30)).is_ok() {
                active.push((port, desc));
            }
        }
        active
    }

    pub fn simulate_process_launch(
        &mut self,
        name: &str,
        pid: u32,
    ) -> (ProcessAction, ProcessEventPayload, bool) {
        let is_prohibited = self.policy.is_prohibited(name);
        self.simulated_processes.insert(name.to_string());
        let payload = ProcessEventPayload {
            pid,
            name: name.to_string(),
            path: Some(format!("/simulated/{name}")),
            cmdline: Some(name.to_string()),
            action: ProcessAction::Started,
            screenshot_attachment: None,
            listening_ports: Vec::new(),
            cpu_usage: None,
            memory_bytes: None,
            is_anomalous_resource: false,
            contest_relative_time: None,
        };
        (ProcessAction::Started, payload, is_prohibited)
    }

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
    fn test_process_collector_lifecycle() {
        let policy = AppPolicy::default();
        let mut collector = ProcessCollector::new(policy);

        let (action, payload, prohibited) = collector.simulate_process_launch("rustc.exe", 9999);
        assert_eq!(action, ProcessAction::Started);
        assert_eq!(payload.pid, 9999);
        assert!(!prohibited);

        let (action_ai, payload_ai, prohibited_ai) =
            collector.simulate_process_launch("ollama.exe", 8888);
        assert_eq!(action_ai, ProcessAction::Started);
        assert_eq!(payload_ai.pid, 8888);
        assert!(prohibited_ai);
    }
}
