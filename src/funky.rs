/*
Custom functions for main.rs in this project
*/

use std::{collections::HashSet, net::{IpAddr, SocketAddr}, string};

async fn snipe(workspace:String, hosts:Vec<SocketAddr>) {
    // runs sn1per per host from input
    for socket in hosts {

    }
}

async fn base_scan(hosts:Vec<String>) -> (HashSet<SocketAddr>){ // base scan to replace the main fn of koboscan
    println!("[I] Sorting into target list");
    let targets: HashSet<IpAddr> =  sort_targets(hosts);
    let live = icmp_scan(targets).await;
    
    
}

/* 
    FUNCTIONS BELOW ARE MIGRATED FROM KOBOSCAN
    https://github.com/jwbaird01/koboscan

    * some may contain updates/edits
*/

fn sort_targets(targets:Vec<String>) -> (HashSet<IpAddr>) {
    /*
    returns the full target IP list as a tuple with (internal,external,domain) Vec<Strings>
     */

    let mut targets: HashSet<IpAddr> = HashSet::new();

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
            domain_targets.insert(target.clone().to_string());
        }
    }
    targets
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

async fn service_detection(sockets:HashMap<IpAddr, HashSet<u16>>) -> Vec<(std::net::SocketAddr, String)> {

    let mut tasks = Vec::new();
    let mut out: Vec<(SocketAddr, String)> = Vec::new();

    for (ip ,ports_set)in sockets{

        let ports:String = ports_set.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");

        let cmd = tokio::spawn(async move {
            let nmap = Command::new("nmap")
                .arg("-p").arg(&ports)
                .arg("-Pn").arg("-sV").arg("-oG").arg("-")
                .arg(ip.to_string())
                .output()
                .await
                .expect("[!] Nmap Failed to Run.");
            nmap
        });
        tasks.push(cmd);
    }
    
    let results = join_all(tasks).await;
    for result in results {
        //println!("{:#?}",&result);
        match result {
            Ok(output) => {
                let tmp_out = String::from_utf8(output.stdout).expect("[!] Failed to convert output to string.");

                let tmp_service_list:Vec<String> = tmp_out.split("Ports: ").nth(1).unwrap_or("").split("\n# Nmap").nth(0).unwrap_or("").split(",").map(str::trim).map(String::from).collect();
                //println!("{:#?}",tmp_service_list);

                let tmp_ip = tmp_out.split("Host: ").nth(1).and_then(|s| s.split(' ').nth(0)).unwrap_or("").to_string();
                
                                
                for service in tmp_service_list {
                    let tmp_port = service.split("/").nth(0).unwrap_or("").to_string();
                    let addr_str = format!("{}:{}", tmp_ip, tmp_port);
                    //println!("{}",tmp_port);
                    let tmp_sock = match addr_str.parse::<std::net::SocketAddr>() {
                        Ok(sock) => sock,
                        Err(_) => {
                            println!("[!] Invalid socket address: {}", addr_str);
                            continue;
                        }
                    };

                    let tmp_service: Vec<&str> = service.split('/').collect();
                    let out_service: String = format!("{}/{}",tmp_service[4],tmp_service[6]);

                    out.push((tmp_sock,out_service));
                }
            }
            Err(e) => eprintln!("[!] Failed task: {e}"),
        }
    }
    out
}

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
