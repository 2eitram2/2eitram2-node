use chrono::Utc;
use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;
use std::net::IpAddr;
use super::super::NODES_HASHMAP;

pub fn check_ts_validity(ts: u64) -> bool {
    let ts = ts / 1000;
    let now = Utc::now().timestamp() as u64;
    let diff = now.saturating_sub(ts);
    diff <= 10 || (ts > now && (ts - now) <= 2)
}

pub async fn send_tcp_message(ip: &IpAddr, buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    let addr: SocketAddr = SocketAddr::new(*ip, 8081);

    for attempt in 1..=3 {
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                stream.write_all(buffer).await?;
                stream.flush().await?;
                println!("Message sent to {}", ip);
                return Ok(());
            }
            Ok(Err(e)) => eprintln!("[Attempt {}] Failed to connect to {}: {}", attempt, ip, e),
            Err(_) => eprintln!("[Attempt {}] Connection to {} timed out", attempt, ip),
        }
        tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
    }
    Err(format!("Failed to send message to {} after 3 attempts", ip).into())
}

pub fn uint8_array_to_ts(arr: &[u8]) -> u64 {
    if arr.len() != 8 {
        panic!("Input array must be exactly 8 bytes long");
    }

    let high = u32::from(arr[0]) << 24
        | u32::from(arr[1]) << 16
        | u32::from(arr[2]) << 8
        | u32::from(arr[3]);

    let low = u32::from(arr[4]) << 24
        | u32::from(arr[5]) << 16
        | u32::from(arr[6]) << 8
        | u32::from(arr[7]);

    ((high as u64) << 32) | low as u64
}

#[derive(Eq, PartialEq)]
struct NodeDistance {
    distance: Vec<u8>,  // XOR distance
    node_ip: String,
}

// Implementing the Ord trait for NodeDistance so that BinaryHeap uses it
impl Ord for NodeDistance {
    fn cmp(&self, other: &Self) -> Ordering {
        // We want the heap to be a min-heap, so we reverse the comparison
        self.distance.cmp(&other.distance)
    }
}

// Implementing PartialOrd for NodeDistance
impl PartialOrd for NodeDistance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub async fn find_closest_nodes(user_id_bytes: &[u8]) -> Result<(String, Vec<String>), &'static str> {
    let start = Utc::now();

    if user_id_bytes.len() < 32 {
        return Err("user_id_bytes must be at least 32 bytes long");
    }

    // Limit to N closest nodes, let's say 6
    let N = 6;

    let mut closest_nodes = BinaryHeap::with_capacity(N);

    let node_hash_map = NODES_HASHMAP.lock().await;

    for (node_ip, node_hash_str) in node_hash_map.iter() {
        let node_hash_bytes = hex::decode(node_hash_str).expect("Invalid hex string for node hash");

        // Compute XOR distance (bitwise difference)
        let distance: Vec<u8> = user_id_bytes.iter()
            .zip(node_hash_bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let node_distance = NodeDistance {
            distance,
            node_ip: node_ip.to_string(),
        };

        // Push the node into the heap
        closest_nodes.push(node_distance);

        // If the heap exceeds the limit, pop the farthest node
        if closest_nodes.len() > N {
            closest_nodes.pop();
        }
    }

    // The heap will now contain only the closest N nodes
    let primary_node_ip = closest_nodes.peek().map_or_else(|| "".to_string(), |x| x.node_ip.clone());

    let fallback_nodes: Vec<String> = closest_nodes.iter()
        .map(|x| x.node_ip.clone())
        .collect();

    let end = Utc::now();
    let duration = end.signed_duration_since(start);
    println!("Took: {}ms", duration.num_milliseconds());

    Ok((primary_node_ip, fallback_nodes))
}



pub fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}