//! Network-connection collector: polls active sockets via [`netstat2`] and
//! emits `NETWORK_CONNECT` for newly-observed TCP connections with a remote
//! peer. The first poll primes the baseline without emitting.

use std::collections::HashSet;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sigil_edr_proto::pb;

use super::{new_event, Collector};

#[derive(Default)]
pub struct NetworkCollector {
    seen: HashSet<String>,
    primed: bool,
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn poll(&mut self) -> Vec<pb::EndpointEvent> {
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto = ProtocolFlags::TCP;
        let sockets = match netstat2::get_sockets_info(af, proto) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "netstat poll failed");
                return Vec::new();
            }
        };

        let mut events = Vec::new();
        let mut current: HashSet<String> = HashSet::new();
        for si in sockets {
            let ProtocolSocketInfo::Tcp(tcp) = &si.protocol_socket_info else {
                continue;
            };
            let remote = tcp.remote_addr.to_string();
            // Skip listeners / unconnected sockets.
            if tcp.remote_port == 0 || remote == "0.0.0.0" || remote == "::" {
                continue;
            }
            let pid = si.associated_pids.first().copied().unwrap_or(0);
            let key = format!(
                "{}:{}->{}:{}/{}",
                tcp.local_addr, tcp.local_port, remote, tcp.remote_port, pid
            );
            current.insert(key.clone());
            if self.primed && !self.seen.contains(&key) {
                let mut ev = new_event(pb::EventKind::NetworkConnect);
                ev.network = Some(pb::NetworkInfo {
                    proto: "tcp".into(),
                    local_addr: tcp.local_addr.to_string(),
                    local_port: tcp.local_port as u32,
                    remote_addr: remote,
                    remote_port: tcp.remote_port as u32,
                    direction: "outbound".into(),
                });
                if pid != 0 {
                    ev.process = Some(pb::Process {
                        pid,
                        ..Default::default()
                    });
                }
                events.push(ev);
            }
        }

        self.seen = current;
        self.primed = true;
        events
    }
}
