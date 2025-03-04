use tokio::sync::Mutex;
use std::fs::File;
use std::io::BufRead;
use std::{
    collections::HashMap, 
    sync::Arc,
};
use std::io::{self};
use std::net::IpAddr;

pub async fn remake_nodes_hashmap(file_path: &str, nodes_hashmap: &Arc<Mutex<HashMap<IpAddr, String>>>) -> io::Result<()> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);

    let mut hashmap = nodes_hashmap.lock().await;

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(":").collect();

        if parts.len() == 2 {
            let ip: IpAddr = parts[0].parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid IP address"))?;
            let hash = parts[1].to_string();
            hashmap.insert(ip, hash);
        }
    }
    println!("{:?}", hashmap);

    Ok(())
}