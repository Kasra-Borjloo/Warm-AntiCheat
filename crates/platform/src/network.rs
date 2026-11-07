use std::collections::HashMap;
use sysinfo::Networks;
use warm_events::{NetworkEventPayload, NetworkInterfaceType};

pub struct NetworkCollector {
    networks: Networks,
    interface_states: HashMap<String, bool>,
    last_wifi_connected: Option<bool>,
    last_wifi_ssid: Option<String>,
    last_wifi_bssid: Option<String>,
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

        let (wifi_conn, wifi_ssid, wifi_bssid) = Self::query_current_wifi();

        Self {
            networks,
            interface_states,
            last_wifi_connected: wifi_conn,
            last_wifi_ssid: wifi_ssid,
            last_wifi_bssid: wifi_bssid,
        }
    }

    pub fn poll_events(&mut self) -> Vec<NetworkEventPayload> {
        let mut events = Vec::new();

        let (wifi_conn, wifi_ssid, wifi_bssid) = Self::query_current_wifi();
        if wifi_conn.is_some()
            && (wifi_conn != self.last_wifi_connected
                || wifi_ssid != self.last_wifi_ssid
                || wifi_bssid != self.last_wifi_bssid)
        {
            let is_connected = wifi_conn.unwrap_or(false);
            self.last_wifi_connected = wifi_conn;
            self.last_wifi_ssid = wifi_ssid.clone();
            self.last_wifi_bssid = wifi_bssid;

            events.push(NetworkEventPayload {
                interface_name: "Wi-Fi".to_string(),
                interface_type: NetworkInterfaceType::WiFi,
                is_connected,
                ssid: if is_connected {
                    wifi_ssid.or_else(|| Some("Wi-Fi Network".to_string()))
                } else {
                    None
                },
            });
        }

        self.networks.refresh();

        for (name, data) in &self.networks {
            let is_connected =
                data.total_packets_received() > 0 || data.total_packets_transmitted() > 0;
            let prev_state = self.interface_states.get(name).copied().unwrap_or(false);

            if is_connected != prev_state {
                self.interface_states.insert(name.clone(), is_connected);
                let iface_type = classify_interface_name(name);
                if iface_type != NetworkInterfaceType::WiFi || events.is_empty() {
                    events.push(NetworkEventPayload {
                        interface_name: name.clone(),
                        interface_type: iface_type,
                        is_connected,
                        ssid: if iface_type == NetworkInterfaceType::WiFi {
                            self.last_wifi_ssid
                                .clone()
                                .or_else(|| Some("Wi-Fi Network".to_string()))
                        } else {
                            None
                        },
                    });
                }
            }
        }

        events
    }

    #[cfg(target_os = "windows")]
    fn query_current_wifi() -> (Option<bool>, Option<String>, Option<String>) {
        use std::process::Command;
        let output = match Command::new("netsh")
            .args(["wlan", "show", "interfaces"])
            .output()
        {
            Ok(out) if out.status.success() => out,
            _ => return (None, None, None),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut state_connected = false;
        let mut ssid = None;
        let mut bssid = None;

        for line in text.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let key = parts[0];
                let val = parts[1];
                if key.eq_ignore_ascii_case("State") {
                    state_connected = val.eq_ignore_ascii_case("connected");
                } else if key.eq_ignore_ascii_case("SSID") && !val.is_empty() {
                    ssid = Some(val.to_string());
                } else if (key.eq_ignore_ascii_case("BSSID")
                    || key.eq_ignore_ascii_case("AP BSSID"))
                    && !val.is_empty()
                {
                    bssid = Some(val.to_string());
                }
            }
        }

        (Some(state_connected), ssid, bssid)
    }

    #[cfg(not(target_os = "windows"))]
    fn query_current_wifi() -> (Option<bool>, Option<String>, Option<String>) {
        (None, None, None)
    }

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
        assert_eq!(classify_interface_name("Wi-Fi"), NetworkInterfaceType::WiFi);
        assert_eq!(
            classify_interface_name("Ethernet 2"),
            NetworkInterfaceType::Ethernet
        );
        assert_eq!(
            classify_interface_name("vEthernet (WSL)"),
            NetworkInterfaceType::Virtual
        );
        assert_eq!(
            classify_interface_name("lo0"),
            NetworkInterfaceType::Loopback
        );
    }
}
