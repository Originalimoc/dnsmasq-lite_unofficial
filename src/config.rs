use std::fs::File;
use std::io::{self, Read, BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use crate::trie::{Hosts, Ipset, Server, TrieMapped};

#[derive(Debug)]
pub struct Config {
    pub full_match_host_records: TrieMapped<Hosts>,
    pub partial_match_host_records: TrieMapped<Hosts>,
    pub server: TrieMapped<Server>,
    pub ipset: TrieMapped<Ipset>,
    pub srv_host: Vec<String>,
    pub bogus_priv: bool,
    pub cache_size: usize,
    pub domain_needed: bool,
    pub interface: Vec<String>,
    pub local_ttl: u32,
    pub max_ttl: u32,
    pub max_cache_ttl: u32,
    pub min_cache_ttl: u32,
    pub no_negcache: bool,
    pub port: u16,
    // pub dnssec: bool,
    // pub trust_anchor: Option<String>,
    // pub proxy_dnssec: bool,
    pub user: Option<String>,
    pub use_stale_cache: u32,
}

impl Config {
    pub fn parse<P: AsRef<Path>>(config_file_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Config {
            full_match_host_records: TrieMapped::new(),
            partial_match_host_records: TrieMapped::new(),
            server: TrieMapped::new(),
            ipset: TrieMapped::new(),
            srv_host: Vec::new(),
            bogus_priv: false,
            cache_size: 0,
            domain_needed: false,
            interface: Vec::new(),
            local_ttl: 5,
            max_cache_ttl: 604800,
            max_ttl: 0,
            min_cache_ttl: 0,
            no_negcache: false,
            port: 53,
            user: None,
            use_stale_cache: 0,
        };
		let mut to_process = std::collections::VecDeque::new();
		to_process.push_back(config_file_path.as_ref().to_path_buf());
	
		while let Some(path) = to_process.pop_front() {
			println!("Processing config: {:?}", path);
			let file = File::open(&path)?;
			let mut reader = BufReader::new(file);
			let mut config_contents = String::new();
			reader.read_to_string(&mut config_contents)?;
			
			for line in config_contents.lines() {
				// dbg!(line);
				if line.trim().is_empty() || line.starts_with('#') {
					continue;
				}
				let parts: Vec<&str> = line.splitn(2, '=').collect();
				match parts[0].trim() {
					"conf-file" => {
						if let Some(file_path) = parts.get(1) {
							to_process.push_back(PathBuf::from(file_path.trim()));
						}
					}
					"conf-dir" => {
						if let Some(dir_spec) = parts.get(1) {
							let parts: Vec<&str> = dir_spec.split(',').collect();
							let dir_path = Path::new(parts[0].trim());
							let extensions: Vec<&str> = parts.iter().skip(1).map(|s| s.trim()).collect();
	
							if dir_path.is_dir() {
								for entry in std::fs::read_dir(dir_path)? {
									let entry = entry?;
									let path = entry.path();
									if path.is_file() {
										let file_name = path.file_name().unwrap().to_str().unwrap();
										let should_load = if extensions.is_empty() {
											!file_name.ends_with('~') && !file_name.starts_with('.') && !file_name.starts_with('#') && !file_name.ends_with('#')
										} else {
											extensions.iter().any(|ext| file_name.ends_with(ext))
										};
	
										if should_load {
											to_process.push_back(path);
										}
									}
								}
							}
						}
					}
					"addn-hosts" => {
						if let Err(e) = Self::parse_hosts_file(parts[1].trim(), &mut config.full_match_host_records) {
							eprintln!("{}:", parts[1].trim());
							Err(e)?
						};
					}
					"address" => {
						Self::parse_address_directive(parts[1].trim(), &mut config.partial_match_host_records)?;
					}
					"host-record" => {
						let sub_parts: Vec<&str> = parts[1].split(',').collect();

						// Find the position where IP addresses start
						let ip_start_index = sub_parts.iter().position(|s| s.parse::<IpAddr>().is_ok()).unwrap_or(sub_parts.len());
						
						let domains = &sub_parts[..ip_start_index];
						let ips: Vec<Hosts> = sub_parts[ip_start_index..]
							.iter()
							.filter_map(|ip| ip.parse().ok().map(Hosts::new))
							.collect();
						
						for domain in domains {
							for ip in &ips {
								config.full_match_host_records.insert(&domain.to_ascii_lowercase(), ip);
							}
						}
					}
					"server" | "local" => {
						Self::parse_server_directive(parts[1].trim(), &mut config.server, &mut config.partial_match_host_records)?;
					}
					"ipset" => {
						Self::parse_ipset_directive(parts[1].trim(), &mut config.ipset)?;
					}
					"srv-host" => config.srv_host.push(parts[1].trim().to_string()),
					"bogus-priv" => config.bogus_priv = true,
					"cache-size" => config.cache_size = parts[1].trim().parse()?,
					"domain-needed" => config.domain_needed = true,
					"interface" => config.interface.push(parts[1].trim().to_string()),
					"local-ttl" => config.local_ttl = parts[1].trim().parse()?,
					"max-cache-ttl" => config.max_cache_ttl = parts[1].trim().parse()?,
					"max-ttl" => config.max_ttl = parts[1].trim().parse()?,
					"min-cache-ttl" => config.min_cache_ttl = parts[1].trim().parse()?,
					"no-negcache" => config.no_negcache = true,
					"port" => config.port = parts[1].trim().parse()?,
					"user" => config.user = Some(parts[1].trim().to_string()),
					"use-stale-cache" => config.use_stale_cache = parts[1].trim().parse().unwrap_or(0),
					"dns-forward-max" | "dnssec" | "trust-anchor" | "proxy-dnssec" | "neg-ttl" | "no-resolv" | "no-poll" | "strict-order" | "no-round-robin" | "all-servers" | "fast-dns-retry" | "dns-loop-detect" => { println!("Ignored config: {}", parts[0].trim()) }
					_ => { eprintln!("Unknown config: {}", parts[0].trim()) } // Ignore unknown directives
				}
            }
        }

        Ok(config)
    }

	pub fn get_hosts(&self, query_name: &str) -> (bool, bool, Vec<crate::trie::Ip>, Vec<crate::trie::Ip>) {
		let mut hosts_matches: Vec<&crate::trie::Ip> = Vec::new();
		hosts_matches.extend(self.partial_match_host_records.search(query_name, false));
		hosts_matches.extend(self.full_match_host_records.search(query_name, true));
		let is_a_blacklisted = hosts_matches
			.iter()
			.any(|host| host.is_unspecified_v4());
		let is_aaaa_blacklisted = hosts_matches
			.iter()
			.any(|host| host.is_unspecified_v6());
		let hosts_a_matches: Vec<_> = {
			if is_a_blacklisted { vec![] } else {
				hosts_matches.iter().filter(|ip| ip.is_ipv4()).map(|&&ip| ip).collect()
			}
		};
		let hosts_aaaa_matches: Vec<_> = {
			if is_aaaa_blacklisted { vec![] } else {
				hosts_matches.iter().filter(|ip| ip.is_ipv6()).map(|&&ip| ip).collect()
			}
		};
		(is_a_blacklisted, is_aaaa_blacklisted, hosts_a_matches, hosts_aaaa_matches)
	}

	pub fn add_to_host_blacklist(&mut self, qtype: simple_dns::resolver::Rtype, domain_name: &str) {
		let v4_unspecified = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
		let v6_unspecified = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
		match qtype {
			simple_dns::resolver::Rtype::A => { self.full_match_host_records.insert(&domain_name.to_ascii_lowercase(), &Hosts::new(v4_unspecified)) },
			simple_dns::resolver::Rtype::AAAA => { self.full_match_host_records.insert(&domain_name.to_ascii_lowercase(), &Hosts::new(v6_unspecified)) },
			_ => {}
		}
	}	

    fn parse_hosts_file<P: AsRef<Path>>(
        path: P,
        full_hosts_trie: &mut TrieMapped<Hosts>,
    ) -> io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                let ip: IpAddr = parts[0].parse().expect("Invalid IP address");
                let domain = parts[1];
                full_hosts_trie.insert(&domain.to_ascii_lowercase(), &Hosts::new(ip));
            }
        }

        Ok(())
    }

    fn parse_address_directive(
        directive: &str,
        partial_hosts_trie: &mut TrieMapped<Hosts>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = directive.split('/').collect();
        let domains = &parts[1..parts.len() - 1];
        let ip_str = parts.last().unwrap();
        if *ip_str == "#" {
			for domain in domains {
				partial_hosts_trie.insert(&domain.to_ascii_lowercase(), &Hosts::new("0.0.0.0".parse()?));
				partial_hosts_trie.insert(&domain.to_ascii_lowercase(), &Hosts::new("::".parse()?));
			}
        } else {
            for domain in domains {
				partial_hosts_trie.insert(&domain.to_ascii_lowercase(), &Hosts::new(ip_str.parse()?));
			}
        };
        
        Ok(())
    }

	fn prepare_and_parse_server_string(server_str_og: &str) -> io::Result<Server> {
		let mut server_str = server_str_og.replace('#', ":");
		if !server_str.contains(':') {
			server_str.push_str(":53");
		}
		let ip_port = server_str.parse();
		let Ok(ip_port) = ip_port else {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("server '{}' invalid", server_str_og),
			));
		};
		Ok(Server::new(ip_port))
	}

	fn parse_server_directive(
		directive: &str,
		server_trie: &mut TrieMapped<Server>,
		partial_hosts_trie: &mut TrieMapped<Hosts>,
	) -> io::Result<()> {
		if !directive.contains('/') {
			let ip_port = Self::prepare_and_parse_server_string(directive)?;
			server_trie.insert_value_to_root(&ip_port);
		} else {
			let parts: Vec<&str> = directive.split('/').collect();
			let domains = &parts[1..parts.len() - 1];
			let server_str = parts.last().unwrap();
	
			if server_str.is_empty() {
				for domain in domains {
					if partial_hosts_trie.search(domain, false).is_empty() {
						Self::parse_address_directive(&format!("address=/{}/0.0.0.0", domain), partial_hosts_trie)
							.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
						Self::parse_address_directive(&format!("address=/{}/::", domain), partial_hosts_trie)
							.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
					} else {
						server_trie.insert(&domain.to_ascii_lowercase(), &Server::new("0.0.0.0:0".parse().unwrap()));
					}
				}
			} else {
				let ip_port = Self::prepare_and_parse_server_string(server_str)?;
				for domain in domains {
					server_trie.insert(&domain.to_ascii_lowercase(), &ip_port);
				}
			}
		}
		Ok(())
	}

	fn parse_ipset_directive(directive: &str, ipset_trie: &mut TrieMapped<Ipset>) -> io::Result<()> {
		let parts: Vec<&str> = directive.split('/').collect();
		let domains = &parts[1..parts.len() - 1];
		let ipset_names_str = parts.last().unwrap();
	
		// Validate ipset names
		for ipset_name in ipset_names_str.split(',') {
			if ipset_trie.value_exist(&Ipset::new(ipset_name)) {
				continue;
			}
			let output = std::process::Command::new("ipset")
				.arg("list")
				.arg(ipset_name)
				.output();
			if output.is_err() {
				log::error!("ERROR: ipset rule set but command failed");
			}
			let output = output?;
			if !output.status.success() {
				let stderr = String::from_utf8_lossy(&output.stderr);
				if stderr.contains("does not exist") {
					return Err(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!("IP set '{}' does not exist", ipset_name),
					));
				} else {
					return Err(io::Error::new(
						io::ErrorKind::Other,
						format!("Failed to validate IP set '{}'", ipset_name),
					));
				}
			}
		}
	
		// Insert each domain with its corresponding IP set names
		for domain in domains {
			for ipset_name in ipset_names_str.split(',') {
				ipset_trie.insert(&domain.to_ascii_lowercase(), &Ipset::new(ipset_name));
			}
		}
		Ok(())
	}
}
