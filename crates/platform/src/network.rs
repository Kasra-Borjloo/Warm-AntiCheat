use std::collections::HashMap;
use sysinfo::Networks;
use warm_events::{NetworkEventPayload, NetworkInterfaceType};

pub struct NetworkCollector {
    networks: Networks,
    interface_states: HashMap<String, bool>,
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCollector {
    pub fn new() -> Self {
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh();

        let mut interface_states = HashMap::new();
        for (name, data) in &networks {
            let is_connected =
                data.total_packets_received() > 0 || data.total_packets_transmitted() > 0;
            interface_states.insert(name.clone(), is_connected);
        }

        Self {
            networks,
            interface_states,
        }
    }

    /// Poll for network interface state changes.
    pub fn poll_events(&mut self) -> Vec<NetworkEventPayload> {
        self.networks.refresh();
        let mut events = Vec::new();

        for (name, data) in &self.networks {
            let is_connected =
                data.total_packets_received() > 0 || data.total_packets_transmitted() > 0;
            let prev_state = self.interface_states.get(name).copied().unwrap_or(false);

            if is_connected != prev_state {
                self.interface_states.insert(name.clone(), is_connected);
                let iface_type = classify_interface_name(name);
                events.push(NetworkEventPayload {
                    interface_name: name.clone(),
                    interface_type: iface_type,
                    is_connected,
                    ssid: if iface_type == NetworkInterfaceType::WiFi {
                        Some("Wi-Fi Network".to_string())
                    } else {
                        None
                    },
                });
            }
        }

        events
    }

    /// Simulate network transition for unit tests.
    pub fn simulate_event(
        &mut self,
        interface_name: &str,
        iface_type: NetworkInterfaceType,
        is_connected: bool,
        ssid: Option<String>,
    ) -> NetworkEventPayload {
        self.interface_states
            .insert(interface_name.to_string(), is_connected);
        NetworkEventPayload {
            interface_name: interface_name.to_string(),
            interface_type: iface_type,
            is_connected,
            ssid,
        }
    }
}

/// Helper classifying interface name into WiFi, Ethernet, Loopback, etc.
pub fn classify_interface_name(name: &str) -> NetworkInterfaceType {
    let lower = name.to_lowercase();
    if lower.contains("vethernet") || lower.contains("vbox") || lower.contains("vmnet") {
        NetworkInterfaceType::Virtual
    } else if lower.contains("wi-fi") || lower.contains("wlan") || lower.contains("wireless") {
        NetworkInterfaceType::WiFi
    } else if lower.contains("eth") || lower.contains("ethernet") || lower.contains("en0") {
        NetworkInterfaceType::Ethernet
    } else if lower.contains("loopback") || lower.contains("lo") {
        NetworkInterfaceType::Loopback
    } else {
        NetworkInterfaceType::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_classification() {
        assert_eq!(
            classify_interface_name("Wi-Fi 2"),
            NetworkInterfaceType::WiFi
        );
        assert_eq!(
            classify_interface_name("Ethernet"),
            NetworkInterfaceType::Ethernet
        );
        assert_eq!(
            classify_interface_name("lo"),
            NetworkInterfaceType::Loopback
        );
        assert_eq!(
            classify_interface_name("vEthernet (WSL)"),
            NetworkInterfaceType::Virtual
        );
    }

    #[test]
    fn test_network_simulation() {
        let mut collector = NetworkCollector::new();
        let ev = collector.simulate_event(
            "wlan0",
            NetworkInterfaceType::WiFi,
            true,
            Some("Sharif-Campus".to_string()),
        );
        assert_eq!(ev.interface_name, "wlan0");
        assert!(ev.is_connected);
        assert_eq!(ev.ssid, Some("Sharif-Campus".to_string()));
    }
}
