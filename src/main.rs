mod config;
mod trie;
mod types;
mod utils;
mod resolv;

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::{Mutex, RwLock};
use tokio::net::UdpSocket;
use tokio::spawn;
use log::{info, warn, error, debug};

use simple_dns::*;
use simple_dns::resolver::*;
use simple_dns::response_builder::*;
use simple_dns::dns_parser::*;

use config::Config;
use trie::{CachedIp, Expirable, Trie, TrieMapped};
use utils::{hash, filter_v4_in_ip_addr, filter_v6_in_ip_addr};
use resolv::{get_resolver_for_server, forward_query_to_upstream};

type ResolverMap = Arc<RwLock<HashMap<SocketAddr, Arc<StubResolver>>>>;
type CacheSet = Arc<Vec<Mutex<Trie<CachedIp>>>>;

const DNS_TIMEOUT: u64 = 2;

fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_file>", args[0]);
        std::process::exit(1);
    }

    let config_file = &args[1];
    let config = Arc::new(RwLock::new(match Config::parse(config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error parsing config file {}: {}", config_file, e);
            std::process::exit(1);
        }
    }));



    let mut rt = tokio::runtime::Builder::new_multi_thread();
    let thread_count = std::thread::available_parallelism()
        .unwrap_or_else(|_| std::num::NonZeroUsize::new(32).unwrap())
        .get();
    let lookup_caches: CacheSet = Arc::new((0..thread_count).map(|_| Mutex::new(Trie::new())).collect());

    let rt = rt
        .enable_all()
        .worker_threads(thread_count)
        .build()
        .expect("Tokio runtime initialization failed");
    info!("Initialized Tokio runtime with {} worker threads", thread_count);

    rt.block_on(run(config, lookup_caches));
}

async fn run(config: Arc<RwLock<Config>>, lookup_caches: CacheSet) {
    let listen_port = config.read().await.port;
    let listen_ipport = format!("0.0.0.0:{}", listen_port);
    let local_addr: SocketAddr = listen_ipport.parse().expect("Invalid listen address");
    let socket = Arc::new(UdpSocket::bind(&local_addr).await.expect("Failed to bind to address"));
    info!("Listening on {}", local_addr);

    let resolver_map: ResolverMap = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let mut buf = vec![0u8; 1600];
        let (size, dns_query_src) = match socket.recv_from(&mut buf).await {
            Ok((s, src)) => (s, src),
            Err(e) => {
                warn!("Failed to receive DNS query: {}", e);
                continue;
            }
        };
        buf.truncate(size);

        let socket = Arc::clone(&socket);
        let config = Arc::clone(&config);
        let resolver_map = Arc::clone(&resolver_map);
        let lookup_caches = Arc::clone(&lookup_caches);
        let max_ttl_for_client = Ttl::from_secs(config.read().await.max_ttl);
        let min_cache_ttl = Ttl::from_secs(config.read().await.min_cache_ttl);
        let max_cache_ttl = Ttl::from_secs(config.read().await.max_cache_ttl);
        let max_stale_cache_ttl = crate::types::time::Ttl::seconds(config.read().await.use_stale_cache.into());

        spawn(async move {
            let (query_name, query_type) = match parse_dns_query(&buf) {
                Some((name, qtype)) => (name.to_lowercase(), qtype),
                None => return,
            };
            let (is_a_blacklisted, is_aaaa_blacklisted, hosts_a_matches, hosts_aaaa_matches) = config.read().await.get_hosts(&query_name);

            #[allow(clippy::type_complexity)]
            async fn handle_dns_response<T, F>(
                hosts_matches: &[trie::Ip],
                ip_filter: F,
                add_response: fn(Vec<u8>, Vec<T>, Ttl, Option<u16>) -> Vec<u8>,
                buf: &[u8],
                config: &Config,
                socket: &UdpSocket,
                dns_query_src: SocketAddr,
            ) -> std::io::Result<()>
            where
                F: Fn(&trie::Ip) -> Option<T>,
                T: Copy,
            {
                let ip_in_hosts: Vec<T> = hosts_matches.iter()
                    .filter_map(ip_filter)
                    .collect();
            
                if !ip_in_hosts.is_empty() {
                    if let Some(response) = build_empty_response(buf) {
                        let response = add_response(response, ip_in_hosts, Ttl::from_secs(config.local_ttl), None);
                        if let Err(e) = socket.send_to(&response, dns_query_src).await {
                            error!("Failed to send DNS response to {}: {}", dns_query_src, e);
                            return Err(e);
                        }
                        return Ok(());
                    } else {
                        error!("Failed to build empty response");
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to build empty response"));
                    }
                }
                
                Ok(())
            }
            match query_type {
                Rtype::A => {
                    if !is_a_blacklisted && !hosts_a_matches.is_empty() {
                        let result = handle_dns_response(
                            &hosts_a_matches,
                            |ip| if let IpAddr::V4(ipv4) = ip.inner() { Some(*ipv4) } else { None },
                            add_a_response,
                            &buf,
                            &*config.read().await,
                            &socket,
                            dns_query_src,
                        ).await;
                        if result.is_ok() { return; };
                    }
                },
                Rtype::AAAA => {
                    if !is_aaaa_blacklisted && !hosts_aaaa_matches.is_empty() {
                        let result = handle_dns_response(
                            &hosts_aaaa_matches,
                            |ip| if let IpAddr::V6(ipv6) = ip.inner() { Some(*ipv6) } else { None },
                            add_aaaa_response,
                            &buf,
                            &*config.read().await,
                            &socket,
                            dns_query_src,
                        ).await;
                        if result.is_ok() { return; };
                    }
                },
                _ => {},
            }

            let (response_type, response) = {
                let cache_index = hash(&query_name) % lookup_caches.len();
                let cache = &lookup_caches[cache_index];
                debug!("Lookup cache for {}, internal cache list id {}", query_name, cache_index);
                let (cached_ipv4, cached_ipv4_actually_expired, cached_ipv6, cached_ipv6_actually_expired, ttl_smallest) = {
                    let mut ttl_smallest = 604800;
                    let expire_max = config.read().await.use_stale_cache;
                    let expire_time_effective = if expire_max == 0 { 3600 } else { expire_max };
                    let cache_read_guard = cache.lock().await;
                    let cached_ip = cache_read_guard.search(&query_name, true);
                    let cached_ip = cached_ip.iter().filter(|ip| !ip.expired(crate::types::time::Ttl::seconds(expire_time_effective.into()))).collect::<Vec<_>>();
                    let cached_ipv4  = cached_ip.iter().filter(|ip| ip.is_ipv4()).collect::<Vec<_>>();
                    let cached_ipv6 = cached_ip.iter().filter(|ip| ip.is_ipv6()).collect::<Vec<_>>();
                    let cached_ipv4_expired = cached_ipv4.iter().all(|ip| {
                        if let Some(remaining_ttl) = ip.remaining_ttl_in_sec() {
                            if remaining_ttl < ttl_smallest {
                                ttl_smallest = remaining_ttl;
                            }
                        }
                        ip.expired(crate::types::time::Ttl::seconds(0))
                    });
                    let cached_ipv6_expired = cached_ipv6.iter().all(|ip| {
                        if let Some(remaining_ttl) = ip.remaining_ttl_in_sec() {
                            if remaining_ttl < ttl_smallest {
                                ttl_smallest = remaining_ttl;
                            }
                        }
                        ip.expired(crate::types::time::Ttl::seconds(0))
                    });
                    (cached_ipv4.iter().filter_map(|ip| match ip.inner() {
                        std::net::IpAddr::V4(v4addr) => Some(*v4addr),
                        _ => None,
                    }).collect::<Vec<Ipv4Addr>>(),
                        cached_ipv4_expired,
                        cached_ipv6.iter().filter_map(|ip| match ip.inner() {
                        std::net::IpAddr::V6(v6addr) => Some(*v6addr),
                        _ => None,
                    }).collect::<Vec<Ipv6Addr>>(),
                    cached_ipv6_expired,
                    ttl_smallest)
                };
                debug!("Lookup cache for {} result: A: {:?}, AAAA: {:?}", query_name, cached_ipv4, cached_ipv6);
                if (is_a_blacklisted && query_type == Rtype::A) || (is_aaaa_blacklisted && query_type == Rtype::AAAA) {
                    (ResponseType::Blocked, build_empty_response(&buf))
                } else {
                    let resolver = get_resolver_for_server(&*config.read().await, &resolver_map, &query_name).await;
                    match resolver {
                        None => {
                            (ResponseType::NoUpstream, build_empty_response(&buf))
                        },
                        Some(resolver) => {
                            if (is_a_blacklisted || is_aaaa_blacklisted) && (query_type == Rtype::A || query_type == Rtype::AAAA || query_type == Rtype::CNAME) {
                                let (cnames_resolved, ip_records_resolved, ttl) = match query_type {
                                    Rtype::A | Rtype::AAAA=> resolve_cname_chain_a_aaaa(&resolver, &query_name, query_type).await,
                                    Rtype::CNAME => {
                                        let cname_result = resolve_cname_depth_one(&resolver, &query_name).await;
                                        cname_result.map(|(cnames, ttl)| (Some(cnames), None, ttl))
                                            .unwrap_or((None, None, Ttl::from_secs(0)))
                                    },
                                    _ => unreachable!(),
                                };
                                if let Some(ref cnames) = cnames_resolved {
                                    for cname in cnames {
                                        match query_type {
                                            Rtype::A | Rtype::AAAA => config.write().await.add_to_host_blacklist(query_type, cname),
                                            Rtype::CNAME => {
                                                if is_a_blacklisted {
                                                    config.write().await.add_to_host_blacklist(Rtype::A, cname)
                                                }
                                                if is_aaaa_blacklisted {
                                                    config.write().await.add_to_host_blacklist(Rtype::AAAA, cname)
                                                }
                                            },
                                            _ => unreachable!(),
                                        }
                                    }
                                }
                                if let Some(empty_response) = build_empty_response(&buf) {
                                    let (cname_only_response, last_cname_len) = if let Some(cnames) = cnames_resolved {
                                        add_cname_response(empty_response, cnames, ttl.min(max_ttl_for_client))
                                    } else {
                                        (empty_response, None)
                                    };
                                    if let Some(ip_records_resolved) = ip_records_resolved {
                                        for ip_record in &ip_records_resolved {
                                            let _ = insert_to_ipset(&config.read().await.ipset, &ip_record.to_string(), &query_name).await;
                                            insert_to_cache(cache, &query_name, *ip_record, ttl, min_cache_ttl, max_cache_ttl).await
                                        }
                                        match query_type {
                                            Rtype::A => {
                                                (ResponseType::Upstream, Some(add_a_response(cname_only_response, filter_v4_in_ip_addr(ip_records_resolved), ttl.min(max_ttl_for_client), last_cname_len)))
                                            }
                                            Rtype::AAAA => {
                                                (ResponseType::Upstream, Some(add_aaaa_response(cname_only_response, filter_v6_in_ip_addr(ip_records_resolved), ttl.min(max_ttl_for_client), last_cname_len)))
                                            },
                                            Rtype::CNAME => {
                                                (ResponseType::Upstream, Some(cname_only_response))
                                            },
                                            _ => unreachable!(),
                                        }
                                    } else {
                                        (ResponseType::UpstreamNX, Some(cname_only_response))
                                    }
                                } else {
                                    (ResponseType::Malformed, None)
                                }
                            } else {
                                let empty_response = build_empty_response(&buf);
                                if let Some(empty_response) = empty_response {
                                    match query_type {
                                        Rtype::A => {
                                            if cached_ipv4_actually_expired {
                                                let upstream_result = resolv::resolve_a(&*config.read().await, &resolver_map, &query_name).await;
                                                if let Some((resolved_ips, ttl)) = upstream_result.1 {
                                                    for resolved_ip in &resolved_ips {
                                                        let _ = insert_to_ipset(&config.read().await.ipset, &resolved_ip.to_string(), &query_name).await;
                                                        insert_to_cache(cache, &query_name, IpAddr::from(*resolved_ip), ttl, min_cache_ttl, max_cache_ttl).await;
                                                    }
                                                    (upstream_result.0, Some(add_a_response(empty_response, resolved_ips, ttl.min(max_ttl_for_client), None)))
                                                } else {
                                                    (upstream_result.0, None)
                                                }
                                            } else {
                                                cache.lock().await.clear(max_stale_cache_ttl);
                                                debug!("Cache found for {}: {:?}, smallest TTL: {}s", query_name, cached_ipv4, ttl_smallest);
                                                let ttl = Ttl::from_secs(ttl_smallest.clamp(0, 604800).try_into().expect("always in range"));
                                                (ResponseType::Cached, Some(add_a_response(empty_response, cached_ipv4, ttl.min(max_ttl_for_client), None)))
                                            }
                                        },
                                        Rtype::AAAA => {
                                            if cached_ipv6_actually_expired {
                                                let upstream_result = resolv::resolve_aaaa(&*config.read().await, &resolver_map, &query_name).await;
                                                if let Some((resolved_ips, ttl)) = upstream_result.1 {
                                                    for resolved_ip in &resolved_ips {
                                                        let _ = insert_to_ipset(&config.read().await.ipset, &resolved_ip.to_string(), &query_name).await;
                                                        insert_to_cache(cache, &query_name, IpAddr::from(*resolved_ip), ttl, min_cache_ttl, max_cache_ttl).await;
                                                    }
                                                    (upstream_result.0, Some(add_aaaa_response(empty_response, resolved_ips, ttl.min(max_ttl_for_client), None)))
                                                } else {
                                                    (upstream_result.0, None)
                                                }
                                            } else {
                                                cache.lock().await.clear(max_stale_cache_ttl);
                                                debug!("Cache found for {}: {:?}, smallest TTL: {}s", query_name, cached_ipv6, ttl_smallest);
                                                let ttl = Ttl::from_secs(ttl_smallest.clamp(0, 604800).try_into().expect("always in range"));
                                                (ResponseType::Cached, Some(add_aaaa_response(empty_response, cached_ipv6, ttl.min(max_ttl_for_client), None)))
                                            }
                                        },
                                        _ => {
                                            forward_query_to_upstream(&*config.read().await, &resolver_map, &query_name, &buf).await
                                        },
                                    }
                                } else {
                                    (ResponseType::Malformed, None)
                                }
                            }
                        }
                    }
                }
            };
            
            // Handle the response
            match response_type {
                ResponseType::Blocked => log::info!("Blocked {} query for {}", query_type, query_name),
                ResponseType::Malformed => log::warn!("Query of {} is malformed", query_name),
                ResponseType::NoUpstream => log::warn!("No upstream server for domain {}", query_name),
                ResponseType::UpstreamErr => log::warn!("Failed to get response of {} from upstream", query_name),
                ResponseType::Cached => log::debug!("Cached response found for {}", query_name),
                ResponseType::TcTcpNotSupported => log::warn!("TC bit set but TCP Query of type {} of {} is not supported, only 1/28/5", query_type, query_name),
                _ => {},
            }
            
            if let Some(response_data) = response {
                if let Err(e) = socket.send_to(&response_data, dns_query_src).await {
                    error!("Failed to send DNS response to {}: {}", dns_query_src, e);
                }
            }
        });
    }
}

async fn insert_to_cache(cache: &Mutex<Trie<CachedIp>>, query_name: &str, ip_record: IpAddr, ttl: Ttl, min_cache_ttl: Ttl, max_cache_ttl: Ttl) {
    let ttl = ttl.clamp(min_cache_ttl, max_cache_ttl);
    cache.lock().await.insert(query_name, CachedIp::new(ip_record, types::time::Ttl::from_std(std::time::Duration::from_secs(ttl.as_secs() as u64)).expect("always in range")));
    info!("{}: {} added to cache", query_name, ip_record);
}

async fn insert_to_ipset(ipset_config: &TrieMapped<trie::Ipset>, ip: &str, query_name: &str) -> std::io::Result<()> {
    let mut anyerror = Ok(());

    let ipset_names = ipset_config.search(query_name, false);

    for ipset in ipset_names {
        let output = tokio::process::Command::new("ipset")
            .arg("add")
            .arg(ipset.name())
            .arg(ip)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stderr_output = String::from_utf8_lossy(&output.stderr);

        if stderr_output.contains("resolving to IPv6 address failed") || stderr_output.contains("resolving to IPv4 address failed") {
            debug!("IP {}({}) not added to ipset {} due to IP family mismatch:\n{}", ip, query_name, ipset.name(), stderr_output.trim());
            continue;
        }

        if stderr_output.contains("already added") {
            debug!("IP {}({}) already exists in ipset {}", ip, query_name, ipset.name());
            continue;
        }

        if output.status.success() {
            debug!("Successfully added {}({}) to ipset {}", ip, query_name, ipset.name());
        } else {
            error!("Failed to add {} to ipset {}", ip, ipset.name());
            anyerror = Err(std::io::Error::new(std::io::ErrorKind::Other, "ipset command failed"));
        }
    }
    anyerror
}
