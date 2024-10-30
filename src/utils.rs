use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn simple_str_hash(query_name: &str) -> usize {
    query_name.bytes().fold(0, |acc, b| acc.wrapping_mul(31).wrapping_add(b as usize))
}

pub use simple_str_hash as hash;

pub fn filter_v4_in_ip_addr(a_records: Vec<IpAddr>) -> Vec<Ipv4Addr> {
	a_records.into_iter().filter_map(|record| {
		if let IpAddr::V4(v4addr) = record {
			Some(v4addr)
		} else {
			None
		}
	}).collect()
}

pub fn filter_v6_in_ip_addr(a_records: Vec<IpAddr>) -> Vec<Ipv6Addr> {
	a_records.into_iter().filter_map(|record| {
		if let IpAddr::V6(v6addr) = record {
			Some(v6addr)
		} else {
			None
		}
	}).collect()
}
