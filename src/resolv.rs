use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use simple_dns::{ResponseType, forward_query, ResponseCode, resolver::{new_resolver, StubResolver, resolve_a as simple_a_resolve, resolve_aaaa as simple_aaaa_resolve}};
use crate::{Config, ResolverMap, DNS_TIMEOUT};

pub async fn forward_query_to_upstream(
    config: &Config,
    resolver_map: &ResolverMap,
    query_name: &str,
    buf: &[u8],
) -> (ResponseType, Option<Vec<u8>>) {
    match get_resolver_for_server(config, resolver_map, query_name).await {
        Some(resolver) => {
            let upstream_server = config.server.search(query_name, false).first().unwrap().inner();
            forward_query(&resolver, &upstream_server, Duration::from_secs(DNS_TIMEOUT), buf).await
        }
        None => (ResponseType::NoUpstream, None),
    }
}

pub async fn resolve_a(
    config: &Config,
    resolver_map: &ResolverMap,
    query_name: &str,
) -> (ResponseCode, ResponseType, Option<(Vec<Ipv4Addr>, simple_dns::resolver::Ttl)>) {
    match get_resolver_for_server(config, resolver_map, query_name).await {
        Some(resolver) => {
            let (rcode, result) = simple_a_resolve(&resolver, query_name).await;
            (rcode, if result.is_none() {
                ResponseType::UpstreamErr
            } else {
                ResponseType::Upstream
            }, result)
        }
        None => (ResponseCode::ServFail, ResponseType::NoUpstream, None),
    }
}

pub async fn resolve_aaaa(
    config: &Config,
    resolver_map: &ResolverMap,
    query_name: &str,
) -> (ResponseCode, ResponseType, Option<(Vec<Ipv6Addr>, simple_dns::resolver::Ttl)>) {
    match get_resolver_for_server(config, resolver_map, query_name).await {
        Some(resolver) => {
            let (rcode, result) = simple_aaaa_resolve(&resolver, query_name).await;
            (rcode, if result.is_none() {
                ResponseType::UpstreamErr
            } else {
                ResponseType::Upstream
            }, result)
        }
        None => (ResponseCode::ServFail, ResponseType::NoUpstream, None),
    }
}

pub async fn get_resolver_for_server(
    config: &Config,
    resolver_map: &ResolverMap,
    query_name: &str,
) -> Option<Arc<StubResolver>> {
    match config.server.search(query_name, false).first() {
        Some(server) => {
            let upstream_server = server.inner();
            Some(get_or_create_resolver(resolver_map, &upstream_server).await)
        }
        None => {
            None
        }
    }
}

async fn get_or_create_resolver(
    resolver_map: &ResolverMap,
    server_addr: &SocketAddr,
) -> Arc<StubResolver> {
    {
        let read_guard = resolver_map.read().await;
        if let Some(resolver) = read_guard.get(server_addr) {
            return Arc::clone(resolver);
        }
    }

    let mut write_guard = resolver_map.write().await;
    let new_resolver = Arc::new(new_resolver(server_addr, Duration::from_secs(DNS_TIMEOUT), false));
    write_guard.insert(*server_addr, Arc::clone(&new_resolver));
    new_resolver
}
