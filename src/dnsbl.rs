//! Asking a blocklist about an address before letting it in.
//!
//! A DNS blocklist is a zone that answers for an address's reversed octets
//! when the address is listed and says nothing when it is not. Every mature
//! IRC server asks one — dronebl, most often — because the addresses that
//! open connections to IRC servers by the thousand are the same ones that do
//! it to everybody else, and somebody has already written them down.
//!
//! It is asked once per address, cached, bounded by a timeout, and it fails
//! open: a resolver that is down must not lock everybody out. Addresses that
//! are not public are never asked about, because the answer would be about
//! somebody else's network.

use crate::config::DnsblConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Addresses whose answers are remembered at once.
const MAX_CACHED: usize = 16384;

/// One or more blocklists, and what to do about a listing.
#[derive(Debug)]
pub struct Dnsbl {
    zones: Vec<String>,
    reject: bool,
    timeout: Duration,
    cache_ttl: Duration,
    /// Address → (the zone that lists it, if any; when that was learned).
    cache: Mutex<HashMap<String, (Option<String>, Instant)>>,
}

impl Dnsbl {
    pub fn from_config(cfg: &DnsblConfig) -> Self {
        Self {
            zones: cfg.zones.clone(),
            reject: cfg.action.eq_ignore_ascii_case("reject"),
            timeout: Duration::from_secs(cfg.timeout_secs.max(1)),
            cache_ttl: Duration::from_secs(cfg.cache_secs.max(1)),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a listing turns a connection away, or is only noted.
    pub fn rejects(&self) -> bool {
        self.reject
    }

    /// The zone that lists `host`, if one does.
    ///
    /// Anything that is not a public address is not asked about. A lookup that
    /// times out counts as not listed: the cost of a wrongly refused person is
    /// theirs, the cost of a resolver outage locking out everybody is
    /// everybody's.
    pub async fn listing(&self, host: &str) -> Option<String> {
        let ip: IpAddr = host.parse().ok()?;
        if !is_public(ip) || self.zones.is_empty() {
            return None;
        }
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock() {
            if let Some((answer, when)) = cache.get(host) {
                if now.duration_since(*when) < self.cache_ttl {
                    return answer.clone();
                }
            }
        }
        let mut listed_in = None;
        for zone in &self.zones {
            let name = query_name(ip, zone);
            match tokio::time::timeout(self.timeout, tokio::net::lookup_host((name, 0u16))).await {
                Ok(Ok(mut answers)) => {
                    if answers.next().is_some() {
                        listed_in = Some(zone.clone());
                        break;
                    }
                }
                Ok(Err(_)) => {} // NXDOMAIN, which is the usual "not listed".
                Err(_) => {
                    tracing::debug!(%host, %zone, "DNSBL lookup timed out; treating as not listed");
                }
            }
        }
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= MAX_CACHED {
                cache.retain(|_, (_, when)| now.duration_since(*when) < self.cache_ttl);
            }
            if cache.len() < MAX_CACHED {
                cache.insert(host.to_string(), (listed_in.clone(), now));
            }
        }
        listed_in
    }
}

/// The name a blocklist answers for: the address reversed, under the zone.
/// IPv4 by octet, IPv6 by nibble — `2001:db8::1` becomes thirty-two nibbles
/// backwards, which is the convention every list uses.
pub fn query_name(ip: IpAddr, zone: &str) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0xf));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.{zone}", nibbles.join("."))
        }
    }
}

/// Whether an address is one a public blocklist could have an opinion about.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_reversed_the_way_every_list_expects() {
        assert_eq!(
            query_name("185.199.108.9".parse().unwrap(), "dnsbl.example"),
            "9.108.199.185.dnsbl.example"
        );
        assert_eq!(
            query_name("2001:db8::1".parse().unwrap(), "dnsbl.example"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example"
        );
    }

    #[test]
    fn nobody_asks_a_public_list_about_a_private_address() {
        assert!(is_public("185.199.108.9".parse().unwrap()));
        assert!(!is_public("203.0.113.9".parse().unwrap()), "a documentation range is nobody's");
        assert!(!is_public("127.0.0.1".parse().unwrap()));
        assert!(!is_public("10.1.2.3".parse().unwrap()));
        assert!(!is_public("192.168.0.9".parse().unwrap()));
        assert!(!is_public("::1".parse().unwrap()));
        assert!(!is_public("fe80::1".parse().unwrap()));
        assert!(!is_public("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_public("2001:db8::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_private_address_and_a_name_are_never_looked_up() {
        let list = Dnsbl::from_config(&DnsblConfig {
            zones: vec!["dnsbl.invalid".into()],
            action: "reject".into(),
            timeout_secs: 1,
            cache_secs: 60,
        });
        assert_eq!(list.listing("127.0.0.1").await, None);
        assert_eq!(list.listing("not-an-address").await, None);
        // And a public one against a zone that cannot answer is not listed,
        // rather than an error that shuts the door.
        assert_eq!(list.listing("185.199.108.9").await, None);
    }

    #[test]
    fn an_answer_is_remembered() {
        let list = Dnsbl::from_config(&DnsblConfig {
            zones: vec!["dnsbl.invalid".into()],
            action: "reject".into(),
            timeout_secs: 1,
            cache_secs: 60,
        });
        list.cache
            .lock()
            .unwrap()
            .insert("185.199.108.9".into(), (Some("dnsbl.invalid".into()), Instant::now()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert_eq!(
            rt.block_on(list.listing("185.199.108.9")),
            Some("dnsbl.invalid".into()),
            "served from the cache without asking anybody"
        );
    }
}
