use tokio::{
    net::TcpListener,
    io::AsyncReadExt,
    sync::Mutex,
};
use std::{
    collections::{HashMap, HashSet}, 
    sync::Arc,
};
use tokio::sync::RwLock;
use bytes::BytesMut;
use std::fs::{OpenOptions, read_to_string};
use std::io::{self, Write};
use std::path::Path;
use std::net::IpAddr;
mod modules;

lazy_static::lazy_static! {
    pub static ref DELAYED_DELIVERY: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

lazy_static::lazy_static! {
    pub static ref REQUEST_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}

lazy_static::lazy_static! {
    pub static ref CONNECTIONS: Arc<RwLock<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>> = Arc::new(RwLock::new(HashMap::new()));
}

lazy_static::lazy_static! {
    pub static ref NODES_HASHMAP: Arc<Mutex<HashMap<IpAddr, String>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = match TcpListener::bind("0.0.0.0:8081").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to port: {}", e);
            return Err(e);
        }
    };
    let _ = modules::load::remake_nodes_hashmap("nodes.txt", &NODES_HASHMAP).await;
    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
                continue;
            }
        };

        tokio::spawn(handle_client(socket, addr));
    }
}

fn append_to_file_if_not_exists(file_path: &str, text: &str) -> io::Result<()> {
    if Path::new(file_path).exists() {
        let content = read_to_string(file_path)?;
        if !content.contains(text) {
            let mut file = OpenOptions::new()
                .append(true)
                .open(file_path)?;

            writeln!(file, "{}", text)?;
            println!("Text appended successfully!");
        } else {
            println!("The text is already in the file.");
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "File does not exist"));
    }

    Ok(())
}

async fn handle_client(
    socket: tokio::net::TcpStream, 
    addr: std::net::SocketAddr,
) {
    let mut buffer = BytesMut::with_capacity(1024);
    let (mut read_half, write_half) = socket.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    let mut user_id = String::new();

    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if n == 0 {
                    if user_id.len() > 0 {
                        let mut connections = CONNECTIONS.write().await;
                        connections.remove(&user_id);
                        println!("{:?}", connections)
                    }
                    break;
                }
                if n < 3 {
                    println!("[ERROR] Invalid packet: too short");
                    buffer.clear();
                    continue;
                }
                let prefix = &buffer[0..3];
                let payload_size_bytes = &buffer[1..3];
                let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
                if buffer.len() < payload_size as usize {
                    continue;
                }
                let unique_request_hash = modules::crypto::sha256_hash(&buffer);
                {
                    let mut hashes = REQUEST_HASHES.lock().await;
                    if hashes.contains(&unique_request_hash) {
                        println!("Duplicate request detected");
                        buffer.clear();
                        continue;
                    }
                    hashes.insert(unique_request_hash);
                }
                match prefix[0] {
                    0 => handle_new_node(&addr).await,
                    1 => modules::handle::handle_connect(&buffer, writer.clone(), &mut user_id).await,
                    2..=4 => modules::handle::forward(&buffer).await,
                    10 => modules::handle::handle_node_assignement(&buffer, writer.clone()).await,
                    _ => println!("Data not recognized"),
                }
                buffer.clear();
            }
            Err(e) => {
                println!("[ERROR] Failed to read from socket: {}", e);
                if user_id.len() > 0 {
                    let mut connections = CONNECTIONS.write().await;
                    connections.remove(&user_id);
                    println!("{:?}", connections)
                }
                break;
            }
        }
    }
}

async fn handle_new_node(addr: &std::net::SocketAddr) {
    println!("New node detected: {}", addr.ip());
    let file_path = "nodes.txt";
    let hash = modules::crypto::sha256_hash(&modules::utils::ip_to_bytes(addr.ip()));
    let text_to_append = format!("{}:{}", addr.ip(), hash);
    let mut hashmap = NODES_HASHMAP.lock().await;
    hashmap.insert(addr.ip(), hash);
    if let Err(e) = append_to_file_if_not_exists(file_path, &text_to_append) {
        eprintln!("Error: {}", e);
    }
}