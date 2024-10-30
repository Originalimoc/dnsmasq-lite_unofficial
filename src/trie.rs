use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use crate::types::time::{Ttl, Instant, now};

pub trait Expirable {
    fn expired(&self, max_expired_time: Ttl) -> bool;
}
// Trait to check for value equality
pub trait InnerValueEq {
    fn is_duplicate(&self, other: &Self) -> bool;
}

#[derive(Debug, PartialEq, Clone)]
pub struct CachedIp { ip: IpAddr, expiration: Option<Instant> }
impl Expirable for CachedIp {
    fn expired(&self, max_expired_time: Ttl) -> bool {
        if let Some(exp) = self.expiration {
            // wrong: exp - now() < max_expired_time aka. now() > exp - max_expired_time
			now() > exp + max_expired_time
        } else {
            false
        }
    }
}
impl InnerValueEq for CachedIp {
    fn is_duplicate(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl CachedIp {
    pub fn new(ip: IpAddr, ttl: Ttl) -> Self {
        CachedIp {
            ip,
            expiration: Some(now() + ttl)
        }
    }
    pub fn inner(&self) -> &IpAddr {
        &self.ip
    }
    pub fn is_ipv4(&self) -> bool {
        self.ip.is_ipv4()
    }
    pub fn is_ipv6(&self) -> bool {
        self.ip.is_ipv6()
    }
    pub fn remaining_ttl_in_sec(&self) -> Option<i64> {
        if let Some(exp_point) = self.expiration {
            let remaining = exp_point - now();
            Some(remaining.num_seconds())
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ipset { name: String }
impl Ipset {
	pub fn new(name: &str) -> Self {
		Self {
			name: name.to_string()
		}
	}
    pub fn name(&self) -> &str {
      &self.name
    }
}
impl InnerValueEq for Ipset {
    fn is_duplicate(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

pub type Hosts = Ip;
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Ip { ip: IpAddr }
impl Ip {
	pub fn new(ip: IpAddr) -> Self {
		Self {
			ip
		}
	}
    pub fn inner(&self) -> &IpAddr {
        &self.ip
    }
    pub fn is_unspecified_v4(&self) -> bool {
        self.ip.is_ipv4() && self.ip.is_unspecified()
    }
    pub fn is_unspecified_v6(&self) -> bool {
        self.ip.is_ipv6() && self.ip.is_unspecified()
    }
    pub fn is_ipv4(&self) -> bool {
        self.ip.is_ipv4()
    }
    pub fn is_ipv6(&self) -> bool {
        self.ip.is_ipv6()
    }
}
impl InnerValueEq for Ip {
    fn is_duplicate(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

pub type Server = IpPort;
#[derive(Debug, PartialEq, Clone)]
pub struct IpPort { ip_port: SocketAddr }
impl IpPort {
	pub fn new(ip_port: SocketAddr) -> Self {
		Self {
			ip_port
		}
	}
    pub fn inner(&self) -> SocketAddr {
        self.ip_port
    }
}
impl InnerValueEq for IpPort {
    fn is_duplicate(&self, other: &Self) -> bool {
        self.ip_port == other.ip_port
    }
}

/// A node in the Trie, holding children nodes and entries.
#[derive(Debug)]
pub struct TrieNode<T> {
    value: Vec<T>,
    children: HashMap<Box<str>, TrieNode<T>>,
}

impl<T: Expirable> TrieNode<T> {
    /// Recursively clears expired entries in the TrieNode.
    fn clear_recursive(&mut self, max_expired_time: Ttl) -> bool {
        self.value.retain(|entry| !entry.expired(max_expired_time));
        self.children.retain(|_, child| child.clear_recursive(max_expired_time));
        !self.value.is_empty() || !self.children.is_empty()
    }
}

/// A Trie structure for storing domain-based mappings.
#[derive(Debug)]
pub struct Trie<T> {
    root: TrieNode<T>,
}

impl<T: InnerValueEq> Trie<T> {
    /// Creates a new empty Trie.
    pub fn new() -> Self {
        Self {
            root: TrieNode {
                children: HashMap::new(),
                value: Vec::new(),
            }
        }
    }
    
	pub fn insert_value_to_root(&mut self, data: T) {
        let node = &mut self.root;
        node.value.retain(|entry| !entry.is_duplicate(&data));
        node.value.push(data);
	}

    /// Inserts a domain with associated data into the Trie.
    pub fn insert(&mut self, domain: &str, data: T) {
        let mut node = &mut self.root;
        for label in domain.rsplit('.') {
            node = node.children.entry(label.into()).or_insert_with(|| TrieNode {
                children: HashMap::new(),
                value: Vec::new(),
            });
        }
        
        // Remove any existing entry that is considered a duplicate
        node.value.retain(|entry| !entry.is_duplicate(&data));
        
        // Add the new data
        node.value.push(data);
    }
    
    /// Searches for a domain in the Trie, returning associated data.
    pub fn search(&self, domain: &str, full_match_only: bool) -> Vec<&T> {
        let mut node = &self.root;
        let mut last_value = node.value.iter().collect();
        let labels: Vec<&str> = domain.rsplit('.').collect();

        for (i, label) in labels.iter().enumerate() {
            if let Some(next_node) = node.children.get(*label) {
                node = next_node;
                if !node.value.is_empty() {
                    last_value = node.value.iter().collect();
                    if full_match_only && i == labels.len() - 1 {
                        return last_value;
                    }
                }
            } else {
                break;
            }
        }

        if full_match_only {
            Vec::new()
        } else {
            last_value
        }
    }
}

impl<T: Expirable> Trie<T> {
    pub fn clear(&mut self, max_expired_time: Ttl) {
        self.root.clear_recursive(max_expired_time);
    }
}

/// An identifier for data stored in the mapping.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct DataId(usize);

impl InnerValueEq for DataId {
	fn is_duplicate(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}

/// A structure to map IDs to actual data, useful for reducing duplication.
#[derive(Debug)]
struct DataMapping<T> {
    data: Vec<T>,
}

impl<T: PartialEq + Clone> DataMapping<T> {
    /// Creates a new empty DataMapping.
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Inserts data into the mapping and returns a unique ID.
    /// If the data already exists, returns the existing ID.
    fn insert(&mut self, data: &T) -> DataId {
        if let Some(index) = self.data.iter().position(|existing| existing == data) {
            DataId(index)
        } else {
            let id = DataId(self.data.len());
            self.data.push(data.clone());
            id
        }
    }

    /// Retrieves data by its ID.
    fn get(&self, id: &DataId) -> Option<&T> {
        self.data.get(id.0)
    }

    fn value_exist(&self, value: &T) -> bool {
        self.data.iter().any(|existing| existing == value)
    }
}

/// A Trie structure for storing domain-based mappings using DataMapping, used for large amount of server/ipset/hosts config load
#[derive(Debug)]
pub struct TrieMapped<T> {
    trie: Trie<DataId>,
    data_mapping: DataMapping<T>,
}

impl<T: InnerValueEq + PartialEq + Clone> TrieMapped<T> {
    /// Creates a new empty TrieMapped.
    pub fn new() -> Self {
        Self {
            trie: Trie::new(),
            data_mapping: DataMapping::new(),
        }
    }

	pub fn insert_value_to_root(&mut self, data: &T) {
        let data_id = self.data_mapping.insert(data);
        self.trie.insert_value_to_root(data_id);
	}

    /// Inserts a domain with associated data into the TrieMapped.
    pub fn insert(&mut self, domain: &str, data: &T) {
        let data_id = self.data_mapping.insert(data);
        self.trie.insert(domain, data_id);
    }

    /// Searches for a domain in the TrieMapped, returning associated data.
    pub fn search(&self, domain: &str, full_match_only: bool) -> Vec<&T> {
        let results = self.trie.search(domain, full_match_only);
        results.into_iter().filter_map(|data_id| self.data_mapping.get(data_id)).collect()
    }

    pub fn value_exist(&self, value: &T) -> bool {
        self.data_mapping.value_exist(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::net::Ipv4Addr;

    // Helper function to create a CachedIp with optional TTL
    fn cached_ip(ip: Ipv4Addr, ttl_seconds: Option<i64>) -> CachedIp {
        CachedIp {
            ip: IpAddr::from(ip),
            expiration: ttl_seconds.map(|secs| now() + Ttl::seconds(secs)),
        }
    }

    #[test]
    fn test_trie() {
        let mut trie = Trie::new();

		// Test insertion
		trie.insert("example.com", cached_ip(Ipv4Addr::new(192, 168, 1, 1), Some(1)));
		trie.insert("www.example.com", cached_ip(Ipv4Addr::new(192, 168, 1, 2), Some(5)));
		trie.insert("sub.example.com", cached_ip(Ipv4Addr::new(192, 168, 1, 3), None)); 
		trie.insert("example.com", cached_ip(Ipv4Addr::new(192, 168, 1, 4), Some(3))); 
		// Test duplicate insertion
		trie.insert("example.com", cached_ip(Ipv4Addr::new(192, 168, 1, 4), Some(15)));

		// Test search with full match
		let result = trie.search("example.com", true);
		assert_eq!(result.len(), 2);

		// Test search with partial match
		let result = trie.search("www.www.example.com", false);
		assert_eq!(result.len(), 1);

		// Test search with partial match
		let result = trie.search("www.www.example.com", true);
		assert_eq!(result.len(), 0);

		// Test search for non-existent domain
		let result = trie.search("google.com", false);
		assert!(result.is_empty());

		// Test TTL expiry
		std::thread::sleep(std::time::Duration::from_secs(3));
		trie.clear(Ttl::seconds(2));
		let result = trie.search("example.com", false);
		assert_eq!(result.len(), 1); 
		let result = trie.search("sub.example.com", false);
		assert_eq!(result.len(), 1);
		let result = trie.search("www.example.com", true);
		assert_eq!(result.len(), 1);

		println!("{:#?}", trie);
    }

    #[test]
    fn test_trie_mapped() {
		let mut ipset_trie = TrieMapped::new(); 
		let mut server_trie = TrieMapped::new();
	
		let ipset1 = Ipset { name: "BlockList1".to_string() };
		let ipset2 = Ipset { name: "BlockList2".to_string() };
		let server1 = IpPort { ip_port: SocketAddr::from_str("10.0.0.1:80").unwrap() };
	
		ipset_trie.insert("example.com", &ipset1);
		ipset_trie.insert("www.example.com", &ipset2);
		ipset_trie.insert("sub.example.com", &ipset1);  
		server_trie.insert("example.net", &server1);
	
		let result = ipset_trie.search("example.com", true);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].name, "BlockList1");
	
		let result = ipset_trie.search("sub.example.com", false);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].name, "BlockList1");
		
		let result = ipset_trie.search("www.example.com", false);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].name, "BlockList2");
	
		let result = ipset_trie.search("www.www.example.com", true);
		assert_eq!(result.len(), 0);
	
		let result = ipset_trie.search("www.www.example.com", false);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].name, "BlockList2"); 
	
		let result = server_trie.search("example.net", true);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].ip_port, SocketAddr::from_str("10.0.0.1:80").unwrap());
	
		let result = server_trie.search("qweqwe.example.net", false);
		assert_eq!(result.len(), 1);
		assert_eq!(result[0].ip_port, SocketAddr::from_str("10.0.0.1:80").unwrap());
	
		let result = server_trie.search("qweqwe.example.net", true);
		assert_eq!(result.len(), 0);
		let result = server_trie.search("qweqwe,example.net", false);
		assert_eq!(result.len(), 0);
	
		println!("{:#?}", ipset_trie);
		println!("{:#?}", server_trie);
    }
}
