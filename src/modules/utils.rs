use chrono::Utc;
use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};
use std::error::Error;
use std::cmp;
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
    // Create a SocketAddr from the IpAddr and port
    let addr: SocketAddr = SocketAddr::new(*ip, 8081);

    for attempt in 1..=3 {
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // Send the message from the buffer
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

pub async fn find_closest_nodes(user_id_bytes: &[u8]) -> Result<(String, Vec<String>), &'static str> {
    if user_id_bytes.len() < 16 {
        return Err("user_id_bytes must be at least 16 bytes long");
    }

    let user_id_int = u128::from_le_bytes(user_id_bytes[0..16].try_into().unwrap());

    let mut distances: Vec<(u128, String)> = {
        let node_hash_map = NODES_HASHMAP.lock().await;
        println!("{:?}", node_hash_map);

        node_hash_map.iter()
            .map(|(node_ip, node_hash_str)| {
                let node_hash_bytes = hex::decode(node_hash_str).expect("Invalid hex string for node hash");
                let node_int = u128::from_le_bytes(node_hash_bytes[0..16].try_into().unwrap());

                let distance = if user_id_int > node_int {
                    user_id_int - node_int
                } else {
                    node_int - user_id_int
                };

                (distance, node_ip.to_string())
            })
            .collect()
    };

    distances.sort_by_key(|k| k.0);

    let primary_node_ip = distances.get(0).map_or_else(|| "".to_string(), |x| x.1.clone());

    let fallback_nodes: Vec<String> = distances[1..cmp::min(distances.len(), 6)]
        .iter()
        .map(|k| k.1.clone())
        .collect();

    Ok((primary_node_ip, fallback_nodes))
}

pub fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}