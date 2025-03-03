use super::crypto;
use super::utils;
use super::super::CONNECTIONS;
use super::super::REQUEST_HASHES;
use super::utils::check_ts_validity;
use tokio::{
    io::AsyncWriteExt,
    sync::Mutex,
};
use std::sync::Arc;
use bytes::BytesMut;
use hex;
use pqc_dilithium::verify;

pub async fn forward(
    buffer: &BytesMut
) {

    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
    
    let signature_length_bytes = &buffer[3..5];
    let signature_length = u16::from_le_bytes([signature_length_bytes[0], signature_length_bytes[1]]) as usize;           
    let signature = &buffer[5..signature_length + 5];
    
    let public_key_bytes = &buffer[signature_length + 5 .. signature_length + 5 + 1952];

    let user_id_bytes = &buffer[signature_length + 5 + 1952 .. signature_length + 32 + 5 + 1952];
    let user_id_hex = hex::encode(user_id_bytes);

    let timestamp_bytes = &buffer[signature_length + 32 + 5 + 1952 .. signature_length + 32 + 5 + 1952 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let data_to_sign_bytes = &buffer[signature_length + 5 .. payload_size];

    if !check_ts_validity(timestamp) {
        println!("[ERROR] Timestamp invalid, dropping message");
    }

    if !verify(signature, data_to_sign_bytes, public_key_bytes).is_ok() {
        println!("[ERROR] Invalid signature, dropping message.");
        return;
    }
    
    
    let connection = {
        let connections = CONNECTIONS.read().await;
        connections.get(&user_id_hex).cloned()
    };
    if let Some(stream) = connection {
        let mut locked_writer = stream.lock().await;
        if let Err(e) = locked_writer.write_all(&buffer).await {
            println!("[ERROR] Failed to write to socket: {}", e);
        } else {
            println!("Message successfully sent to {}", user_id_hex);
        }
    }
    else {
        println!("No connection for {}", user_id_hex);
        let result = utils::find_closest_nodes(user_id_bytes).await;
        println!("{:?}", result);
    }
}

pub async fn handle_connect(
    buffer: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>
) {
    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    let signature_length_bytes = &buffer[3..5];
    let signature_length = u16::from_le_bytes([signature_length_bytes[0], signature_length_bytes[1]]) as usize;           
    let signature = &buffer[5..signature_length + 5];
    
    let public_key_bytes = &buffer[signature_length + 5 .. signature_length + 5 + 1952];
    let data_to_sign_bytes = &buffer[signature_length + 5 .. payload_size];

    let timestamp_bytes = &buffer[signature_length + 5 + 1952 .. payload_size];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);
    let result = verify(signature, data_to_sign_bytes, public_key_bytes).is_ok();
    if !result {
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        return;
    }

    let public_id = crypto::sha256_hash(&public_key_bytes);
    
    let unique_request_hash = crypto::sha256_hash(&buffer);
    {
        let mut hashes = REQUEST_HASHES.lock().await;
        if hashes.contains(&unique_request_hash) {
            println!("Duplicate request detected");
            return;
        }
        hashes.insert(unique_request_hash);
    }

    {
        let mut conn_map = CONNECTIONS.write().await;
        conn_map.insert(public_id.clone(), Arc::clone(&writer));
    }
    println!("Connexion request properly formated");
}

pub async fn handle_node_assignement(
    buffer: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>
) {
    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    let signature_length_bytes = &buffer[3..5];
    let signature_length = u16::from_le_bytes([signature_length_bytes[0], signature_length_bytes[1]]) as usize;           
    let signature = &buffer[5..signature_length + 5];
    
    let public_key_bytes = &buffer[signature_length + 5 .. signature_length + 5 + 1952];
    let data_to_sign_bytes = &buffer[signature_length + 5 .. payload_size];

    let timestamp_bytes = &buffer[signature_length + 5 + 1952 .. payload_size];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);
    let result = verify(signature, data_to_sign_bytes, public_key_bytes).is_ok();
    if !result {
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        return;
    }

    let public_id_hex = crypto::sha256_hash(&public_key_bytes);
    let public_id = hex::decode(&public_id_hex).unwrap();
    println!("{}", &public_id_hex);
    match utils::find_closest_nodes(&public_id).await {
        Ok((primary_node_ip, fallback_nodes)) => {
            let mut buffer = BytesMut::with_capacity(1024);
            buffer.extend_from_slice(&[0x0a, 0x00, 0x00]);
            buffer.extend_from_slice(primary_node_ip.as_bytes());
            buffer.extend_from_slice(" ".as_bytes());
            println!("Primary node {:?} \nFallbackNodes{:?}", primary_node_ip, fallback_nodes);
            // Include fallback nodes if any
            for node_ip in fallback_nodes {
                buffer.extend_from_slice(node_ip.as_bytes());
                buffer.extend_from_slice(" ".as_bytes());
            }

            let mut locked_writer = writer.lock().await;
            locked_writer.write_all(&buffer).await.expect("Write failed");
        }
        Err(_) => {
            println!("Error while finding closest nodes");
        }
    }
}