/*
Custom functions for main.rs in this project

 - Noticed that merging the internal and external scans will cause external services that block icmp not return... should fix
 - using the IP may not work in all cases.. need to store the domains as well as the IPs before feeding to sn1per

*/

use std::{collections::HashSet, hash::Hash, net::{IpAddr, SocketAddr}, string};

async fn snipe(workspace:String, hosts:Vec<SocketAddr>) {
    // runs sn1per per host from input
    for socket in hosts {
        //sniper -t <TARGET_IP> -m port -p <PORT_NUMBER> -o
    }
}

async fn base_scan(hosts:Vec<String>) -> (HashMap<IpAddr, HashSet<u16>>,HashSet<String>){ // base scan to replace the main fn of koboscan
    println!("[I] Sorting into target list");
    let (targets,domains) =  sort_targets(hosts);
    let live: Vec<IpAddr> = icmp_scan(targets).await;

        // Scanner setup for rustscan

    let range: PortRange = PortRange {
        start: 1,
        end:65535 //range needs to be set with arg..
    };
    let strat: PortStrategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
    let threads: u16 = 5000; //should be set by args
    let scanner: Scanner = Scanner::new(&internal_pinged, threads, Duration::from_millis(1000), 1, false, strat, true, vec![9100,9101,9102], false);
        
        // starting scans 

    let mut ports:Vec<SocketAddr> = Vec::new();
    if !live.is_empty() {
        ports = block_on(internal_scanner.run());
        //println!("Internal Results: {:?}",i_ports);
    } else {
        eprintln!("[!] No targets are live");
    }

    let deduped: HashMap<IpAddr, HashSet<u16>> = dedupe_sockets(ports);
    (deduped,domains)
}

/* 
    FUNCTIONS BELOW ARE MIGRATED FROM KOBOSCAN
    https://github.com/jwbaird01/koboscan

    * some may contain updates/edits
*/

fn sort_targets(targets:Vec<String>) -> (HashSet<IpAddr>,HashSet<String>) {
    /*
    returns the full target IP list as a tuple with (internal,external,domain) Vec<Strings>
     */

    let mut targets: HashSet<IpAddr> = HashSet::new();
    let mut domains:HashSet<String> = HashSet::new();

    let domain_re = Regex::new(r#"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"#).expect("[!] Not a Domain");

    for target in &targets {
        if target.contains("/") {
            if let Ok(net) = target.parse::<IpNet>() {
                for ip in net.hosts() {
                    if ip.to_canonical().is_ipv4() {
                        if let IpAddr::V4(v4) = ip {
                            if v4.is_private() {
                                targets.insert(ip);
                                _ = v4.is_private();
                            } else {
                                targets.insert(ip);
                                _ = v4.is_private();
                            }
                        }
                    } else if ip.to_canonical().is_ipv6() {
                        if let IpAddr::V6(v6) = ip {
                            if v6.is_unique_local() {
                                targets.insert(ip);
                            } else {
                                targets.insert(ip);
                            }
                        }
                    }
                }
            } 
        } else {
            match target.parse::<IpAddr>() {
                Ok(ip) => {
                    match ip {
                        IpAddr::V4(v4) => if v4.is_private() {
                            targets.insert(ip);
                        } else {
                            targets.insert(ip);
                        },
                        IpAddr::V6(v6) => if v6.is_unique_local(){
                            targets.insert(ip);
                        } else {
                            targets.insert(ip); 
                        },
                    }
                }
                Err(e) => eprintln!("[!] Invalid IP address found: {}", e)
            }
        }
        if domain_re.is_match(&target) {
            domains.insert(target.clone().to_string());
        }
        let d_hostaddr = nslookup(domains.clone());
        for d_target in d_hostaddr {
            targets.insert(d_target);
        }
    }
    (targets,domains)
}

fn nslookup(domains:HashSet<String>) -> HashSet<IpAddr> {
    let mut addresses:HashSet<IpAddr> = HashSet::new();

    for domain in domains {
        match lookup_host(&domain) {
            Ok(ips) => {
                for ip in ips {
                    addresses.insert(ip);
                }
            }
            Err(_e) => {}
        }
    }
    addresses
}

async fn icmp_scan(targets:HashSet<IpAddr>,) -> (Vec<IpAddr>) {

    let mut tasks = Vec::new();
    let mut o_targets: Vec<IpAddr> = Vec::new();

    for trg in targets {
        tasks.push(tokio::spawn(surge_ping::ping(eip, &[0;8])));
    }

    let results = join_all(tasks).await;

    for result in results {
        match result {
            Ok(Ok((packet, _duration))) => {
                let source_ip: IpAddr = match packet {
                        IcmpPacket::V4(p) => p.get_source().into(),
                        IcmpPacket::V6(p) => p.get_source().into(),
                    };
                    if source_ip.to_canonical().is_ipv4() {
                        if let IpAddr::V4(v4) = source_ip {
                            if v4.is_private() {
                                o_targets.push(source_ip);
                                _ = v4.is_private();
                            }
                        }
                    } else if source_ip.to_canonical().is_ipv6() {
                        if let IpAddr::V6(v6) = source_ip {
                            if v6.is_unique_local() {
                                o_targets.push(source_ip);
                            }
                        }
                    }
                }
                Ok(Err(surge_error)) => {
                        eprintln!("[!] Ping operation failed: {:?}", surge_error);
                    }
                    Err(join_error) => {
                        eprintln!("[!] Failed to join task: {}", join_error);
                    }
            }
        }
        o_targets
}

/*

    Service Detection is not needed since Sn1per will do it anyway.

*/

fn to_hashmap(services:Vec<(SocketAddr, String)>) -> HashMap<String,HashSet<SocketAddr>>{
    let mut out_map: HashMap<String,HashSet<SocketAddr>> = HashMap::new();
    for (socket,service) in services {
        out_map.entry(service).or_insert_with(HashSet::new).insert(socket);
    }
    out_map
}

fn dedupe_sockets(sockets:Vec<SocketAddr>) -> HashMap<IpAddr,HashSet<u16>> {
    let mut sorted: HashMap<IpAddr,HashSet<u16>> = HashMap::new();
    for socket in sockets {
        sorted.entry(socket.ip()).or_insert_with(HashSet::new).insert(socket.port());
    }
    sorted
}
