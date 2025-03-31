use super::crypto;
use super::utils;
use super::super::CONNECTIONS;
use super::utils::check_ts_validity;
use tokio::{
    io::AsyncWriteExt,
    sync::Mutex,
};
use std::net::IpAddr;
use std::sync::Arc;
use bytes::BytesMut;
use hex;
use pqc_dilithium::verify;
use ed25519_dalek::{PublicKey, Signature, Verifier};

pub async fn forward(
    buffer: &BytesMut
) {

    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    let dilithium_signature = &buffer[5 .. 5 + 3293];
    let ed25519_signature = &buffer[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &buffer[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];

    let user_id_bytes = &buffer[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 32];
    let user_id_hex = hex::encode(user_id_bytes);

    let timestamp_bytes = &buffer[5 + 3293 + 64 + 1952 + 32 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let data_to_sign_bytes = &buffer[5 + 3293 + 64 .. payload_size];

    if !check_ts_validity(timestamp) {
        println!("[ERROR] Timestamp invalid, dropping message");
    }

    if !verify(&dilithium_signature, &data_to_sign_bytes, &dilithium_public_key_bytes).is_ok() {
        println!("[ERROR] Invalid signature, dropping message.");
        return;
    }
    
    match PublicKey::from_bytes(ed25519_public_key) {
        Ok(public_key) => {
            let signature = Signature::from_bytes(ed25519_signature).unwrap();
            match public_key.verify(data_to_sign_bytes, &signature) {
                Ok(_) => println!("✅ Ed25519 Signature is valid!"),
                Err(_) => return,
            }
        },
        Err(_) => return,
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
        match utils::find_closest_nodes(user_id_bytes).await {
            Ok((primary_node_ip, _)) =>{
                let ip: IpAddr = primary_node_ip.parse().expect("Invalid IP address");
                if ip!= IpAddr::V4(std::net::Ipv4Addr::new(0,0,0,0)) {
                    let _ = utils::send_tcp_message(&ip, &buffer, user_id_hex).await;
                }
            }
            _ => {
                println!("Error while finding closest nodes");
            }
        }
    }
}

pub async fn handle_connect(
    buffer: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    user_id:  &mut String
) {
    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
   
    let dilithium_signature = &buffer[5 .. 5 + 3293];
    let ed25519_signature = &buffer[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &buffer[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let nonce = &buffer[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 16];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64 .. payload_size];
    
    let timestamp_bytes = &buffer[5 + 3293 + 64 + 1952 + 32 + 16 .. payload_size];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    match PublicKey::from_bytes(ed25519_public_key) {
        Ok(public_key) => {
            let signature = Signature::from_bytes(ed25519_signature).unwrap();
            match public_key.verify(data_to_sign_bytes, &signature) {
                Ok(_) => println!("✅ Ed25519 Signature is valid!"),
                Err(_) => return,
            }
        },
        Err(_) => return,
    }
    let result = verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).is_ok();
    if !result {
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        return;
    }
    let full_hash_input = [
        &dilithium_public_key_bytes[..],
        &ed25519_public_key[..],         
        &nonce[..],                      
    ].concat();

    let public_id = crypto::sha256_hash(&full_hash_input);

    user_id.push_str(&public_id);
    {
        let mut conn_map = CONNECTIONS.write().await;
        conn_map.insert(public_id.clone(), Arc::clone(&writer));
    }
    {
        let user_packets = utils::get_packets_for_user(&public_id).await;
        match user_packets {
            Some(packets) => {
                let mut locked_writer = writer.lock().await;

                for packet in packets {
                    let _ = locked_writer.write_all(&packet).await;
                }
    
                println!("All packets for user {} have been processed.", public_id);
                utils::delete_packets_for_user(&public_id).await;
            }
            None => {
                println!("No packets found for user {}", public_id);
            }
        }
    }
    println!("Connexion request properly formated");
}

pub async fn handle_node_assignement(
    buffer: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>
) {
    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    let signature = &buffer[5..3293 + 5];
    
    let public_key_bytes = &buffer[3293 + 5 .. 3293 + 5 + 1952];
    let data_to_sign_bytes = &buffer[3293 + 5 .. payload_size];

    let timestamp_bytes = &buffer[3293 + 5 + 1952 + 16 .. payload_size];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);
    let result = verify(signature, data_to_sign_bytes, public_key_bytes).is_ok();
    if !result {
        println!("Invalid signature");
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        println!("Invalid timestamp");
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