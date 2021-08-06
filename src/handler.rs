#![allow(dead_code)]
#[path = "logging.rs"]
pub mod logging;
#[path = "varint.rs"]
mod varint;
#[path = "byteutils.rs"]
mod byteutils;
use aes::Aes128;
use cfb8::cipher::{AsyncStreamCipher, NewCipher};
use cfb8::Cfb8;
use logging::logger;
use rsa::{PaddingScheme, RSAPrivateKey, RSAPublicKey};
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};
use std::{
    io::{Read, Write},
    net::{TcpStream},
};
pub struct User {
    username: Arc<Mutex<String>>,
}
type AesCfb8 = Cfb8<Aes128>;
pub struct Handler {}
#[derive(Debug)]
struct HandshakeC2S {
    protocol_version: u32,
    server_address: String,
    server_port: u16,
    next_state: u8,
}
struct LoginStartC2S {
    username: String,
}
struct EncryptionRequestS2C {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}
struct EncryptionResponseC2S {
    shared_secret: Vec<u8>,
    verify_token: Vec<u8>,
}
impl Handler {
    pub fn from_stream(
        mut stream: TcpStream,
        logger: logger::Logger,
        rsa_key: Arc<Mutex<RSAPrivateKey>>,
    ) -> std::io::Result<()> {
        let mut version_hashmap = std::collections::HashMap::new();
        let mut old_version_hashmap = std::collections::HashMap::new();
        old_version_hashmap.insert(29, "1.2.4-1.2.5");
        version_hashmap.insert(755, "1.17");
        version_hashmap.insert(754, "1.16.5/1.16.4");
        version_hashmap.insert(753, "1.16.3");
        version_hashmap.insert(751, "1.16.1");
        version_hashmap.insert(340, "1.12.2");
        version_hashmap.insert(5, "1.7.6-1.7.10");
        version_hashmap.insert(4, "1.7.2-1.7.5");
        version_hashmap.insert(3, "1.7-1.7.1");
        let hac2s = HandshakeC2S::parse(&mut stream)?;
        match hac2s.next_state {
            2 => {}
            _ => {
                return Ok(());
            }
        }
        let lsc2s = LoginStartC2S::parse(&mut stream)?;
        logger.log_info(&format!("User {} logging in..", lsc2s.username))?;
        if hac2s.protocol_version != 756 {
            logger.log_warn(&format!("User {} is trying to join with protocol version {}, but we are on 756!", lsc2s.username, hac2s.protocol_version))?;
            let mut clientver = "an unknown version".to_owned();
            let cv2 = match version_hashmap.get(&hac2s.protocol_version) {
                Some(ver) => Some(ver),
                None => None
            };
            if !cv2.is_none() {
                clientver = cv2.unwrap().to_string();
            }
            stream.write(&write_s2c_login_disconnect(&format!("Incorrect client version. We are on 1.17.1!, you are on {}!\nDiscord: https://discord.gg/2nBuwC6PkZ", clientver)))?;
            return Err(Error::new(ErrorKind::Other, "Incorrect client version."));
        }
        let key = retrieve_key(rsa_key.clone());
        let public_key = RSAPublicKey::from(&key);
        let public_key = format_rsa_key(&public_key);
        let vtoken = gen_vtoken();
        let ers2c = EncryptionRequestS2C {
            server_id: "".to_string(),
            public_key: public_key.clone(),
            verify_token: vtoken.clone(),
        };
        let ers2c = ers2c.as_bytes();
        stream.write(&ers2c)?;
        let erc2s = EncryptionResponseC2S::parse(&mut stream, key)?;
        if erc2s.verify_token != vtoken {
            return Err(Error::new(ErrorKind::Other, "Verify token mismatch!"));
        }
        let sharedsecret = erc2s.shared_secret;
        let mut cipher: AesCfb8 =
        AesCfb8::new_from_slices(&sharedsecret.clone(), &sharedsecret.clone()).unwrap();
    let mut cipher2: AesCfb8 =
        AesCfb8::new_from_slices(&sharedsecret.clone(), &sharedsecret.clone()).unwrap();
        let verification = verify_against_mojang("".to_string(), sharedsecret.clone(), public_key.clone(), lsc2s.username.clone());
        match verification.as_str() {
            "200" => {
                logger.log_info(&format!("Successful authentication of user {}", lsc2s.username.clone()))?;
            }
            code => {
                logger.log_warn(&format!("Failed to authenticate user {}, status code {}", lsc2s.username.clone(), code))?;
                let mut packet = write_s2c_login_disconnect("Failed to authenticate with Mojang authentication servers."); 
                cipher.encrypt(&mut packet);
                stream.write(&packet)?;
                return Err(Error::new(ErrorKind::Other, "Failed to authenticate."));
            }
        }
        let outgoing = TcpStream::connect("127.0.0.1:25595");
        if outgoing.is_err() {
            let mut packet = write_s2c_login_disconnect("Can't establish connection to server. Please try again later.\nDiscord: https://discord.gg/2nBuwC6PkZ");
            cipher.encrypt(&mut packet);
            stream.write(&packet)?;
            return Err(Error::new(ErrorKind::Other, "Server connection refused"));
        }
        let mut outgoing = outgoing.unwrap();
        outgoing.write_all(&hac2s.as_bytes()?)?;
        outgoing.write_all(&lsc2s.as_bytes()?)?;
        let mut outgoing2 = outgoing.try_clone()?;
        let mut stream2 = stream.try_clone()?;
        let exit = Arc::new(Mutex::new(false));
        let exit2 = exit.clone();
        let username = lsc2s.username.clone();
        let username2 = username.clone();
        let logger2 = logger.clone();
        let logger1 = logger.clone();
        let thread1 = std::thread::spawn(move || {
            loop {
                let exityes = exit.lock().unwrap();
                if *exityes {
                    logger1.log_info(&format!("Closing clientbound thread for user {}", username)).unwrap();
                    drop(exityes);
                    break;
                }
                drop(exityes);
                let packet = varint::VarInt::read_varint_prefixed_bytearray(&mut outgoing);
                if packet.is_err() {
                    let mut exityes = exit.lock().unwrap();
                    *exityes = true;
                    drop(exityes);
                    logger1.log_info(&format!("Closing serverbound thread for user {}", username)).unwrap();
                    break;
                }
                let packet = varint::VarInt::write_varint_prefixed_bytearray(packet.unwrap());
                let mut packet = s2c_packet_modification(packet);
                cipher.encrypt(&mut packet);
                stream.write(&packet).unwrap(); 
            }
        });
        let thread2 = std::thread::spawn(move || {
            loop {
                let packet = varint::VarInt::enc_read_varint_prefixed_bytearray(&mut stream2, &mut cipher2);
                if packet.is_err() {
                    let mut exityes = exit2.lock().unwrap();
                    *exityes = true;
                    drop(exityes);
                    logger2.log_info(&format!("Closing serverbound thread for user {}", username2)).unwrap();
                    break;
                }
                let packet = varint::VarInt::write_varint_prefixed_bytearray(packet.unwrap());
                let packet = c2s_packet_modification(packet);
                let write = outgoing2.write(&packet);
                if write.is_err() {
                    let mut exityes = exit2.lock().unwrap();
                    *exityes = true;
                    drop(exityes);
                    logger2.log_info(&format!("Closing serverbound thread for user {}", username2)).unwrap();
                    break;
                }
                let exityes = exit2.lock().unwrap();
                if *exityes {
                    logger2.log_info(&format!("Closing serverbound thread for user {}", username2)).unwrap();
                    drop(exityes);
                    break;
                }
                drop(exityes); 
            }
        });
        thread1.join().unwrap();
        thread2.join().unwrap();
        logger.log_info(&format!("Disconnecting user {}", lsc2s.username))?;
        Ok(())
    }
}
impl HandshakeC2S {
    pub fn parse(mut stream: &mut dyn std::io::Read) -> std::io::Result<Self> {
        let (packetid, packet) = varint::VarInt::read_packet(&mut stream)?;
        match packetid {
            0x00 => {
                let mut packet = std::io::Cursor::new(packet);
                let protocol_ver = varint::VarInt::new_from_bytes(&mut packet).unwrap().number;
                let server_address = varint::VarInt::read_string(&mut packet);
                let server_port = varint::VarInt::read_unsigned_short(&mut packet);
                let next_state = varint::VarInt::new_from_bytes(&mut packet).unwrap().number;
                return Ok(Self {
                    protocol_version: protocol_ver,
                    server_address: server_address,
                    server_port: server_port as u16,
                    next_state: next_state as u8,
                });
            }
            _ => {
                return Err(Error::new(ErrorKind::Other, "Got a weird packet!"));
            }
        }
    }
    pub fn as_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut packet = vec![];
        packet.append(&mut varint::VarInt::new_as_bytes(self.protocol_version.clone()));
        packet.append(&mut varint::VarInt::write_string(self.server_address.clone()));
        packet.append(&mut varint::VarInt::write_unsigned_short(self.server_port.clone()));
        packet.append(&mut varint::VarInt::new_as_bytes(self.next_state.clone() as u32));
        let packet = varint::VarInt::galax_write_packet(packet, 0x00);
        return Ok(packet);
    }
}
impl LoginStartC2S {
    pub fn parse(mut stream: &mut dyn std::io::Read) -> std::io::Result<Self> {
        let (packetid, packet) = varint::VarInt::read_packet(&mut stream)?;
        match packetid {
            0x00 => {
                let mut packet = std::io::Cursor::new(packet);
                let username = varint::VarInt::read_string(&mut packet);
                return Ok(Self { username: username });
            }
            _ => {
                return Err(Error::new(ErrorKind::Other, "Got a weird packet!"));
            }
        }
    }
    pub fn as_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut packet = vec![];
        packet.append(&mut varint::VarInt::write_string(self.username.clone()));
        let packet = varint::VarInt::galax_write_packet(packet, 0x00);
        return Ok(packet);
    }
}
impl EncryptionRequestS2C {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut packet = vec![];
        packet.append(&mut varint::VarInt::write_string(self.server_id.clone()));
        packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(
            self.public_key.clone(),
        ));
        packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(
            self.verify_token.clone(),
        ));
        let packet = varint::VarInt::galax_write_packet(packet, 0x01);
        return packet;
    }
}
impl EncryptionResponseC2S {
    pub fn parse(mut stream: &mut dyn std::io::Read, key: RSAPrivateKey) -> std::io::Result<Self> {
        let (packetid, packet) = varint::VarInt::read_packet(&mut stream)?;
        match packetid {
            0x01 => {
                let mut stream = std::io::Cursor::new(packet);
                let encss = varint::VarInt::read_varint_prefixed_bytearray(&mut stream)?;
                let encvt = varint::VarInt::read_varint_prefixed_bytearray(&mut stream)?;
                let padding = PaddingScheme::new_pkcs1v15_encrypt();
                let sharedsecret = key.decrypt(padding, &encss).expect("Failure to decrypt");
                let padding = PaddingScheme::new_pkcs1v15_encrypt();
                let verifytoken = key.decrypt(padding, &encvt).expect("Failure to decrypt");
                return Ok(Self {shared_secret: sharedsecret, verify_token: verifytoken});
            }
            _ => {
                return Err(Error::new(ErrorKind::Other, "Got a weird packet!"));
            }
        }
    }
}

fn format_rsa_key(pkey: &RSAPublicKey) -> Vec<u8> {
    use rsa::PublicKeyParts;
    let public_key_encoded =
        rsa_der::public_key_to_der(&pkey.n().to_bytes_be(), &pkey.e().to_bytes_be());
    return public_key_encoded;
}

fn retrieve_key(key: Arc<Mutex<RSAPrivateKey>>) -> RSAPrivateKey {
    let key2 = key.lock().unwrap();
    let key3 = key2.clone();
    drop(key2);
    return key3;
}
fn gen_vtoken() -> Vec<u8> {
    use rand::RngCore;
    let mut vtoken = vec![0; 4];
    rand::thread_rng().fill_bytes(&mut vtoken);
    return vtoken;
}

fn c2s_packet_modification(input: Vec<u8>) -> Vec<u8> {
    let original = input.clone();
    let mut packet = std::io::Cursor::new(input);
    let (packetid, packet) = varint::VarInt::read_packet(&mut packet).unwrap();
    if packetid == 0x03 {
        let mut packet = std::io::Cursor::new(packet);
        let string = varint::VarInt::read_string(&mut packet);
        let mut newpacket = vec![];
        newpacket.append(&mut varint::VarInt::write_string(string.chars().rev().collect::<String>()));
        let newpacket = varint::VarInt::galax_write_packet(newpacket, 0x03);
        return newpacket;
    }
    return original.clone();
}
fn s2c_packet_modification(input: Vec<u8>) -> Vec<u8> {
    let original = input.clone();
    return original.clone();
}
fn write_s2c_login_disconnect(msg: &str) -> Vec<u8> {
    let mut packet = vec![];
    packet.append(&mut varint::VarInt::write_string(format!(r#"{{"text":"{}"}}"#, msg)));
    let packet = varint::VarInt::galax_write_packet(packet, 0x00);
    return packet;
}
pub fn verify_against_mojang(server_id: String, shared_secret: Vec<u8>, encoded_public_key: Vec<u8>, username: String) -> String {
    use num_bigint::{BigInt};
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(server_id.as_bytes());
    hasher.update(shared_secret.clone());
    hasher.update(encoded_public_key.clone());
    let hash = hasher.finalize();
    let finalhash = BigInt::from_signed_bytes_be(&hash);
    let finalhash = format!("{:x}", finalhash);
    let response = format!(
        "GET /session/minecraft/hasJoined?username={username}&serverId={hash} HTTP/1.1\r\nHost: sessionserver.mojang.com\r\nConnection: close\r\n\r\n",
        username = username,
        hash = finalhash
    );
    extern crate native_tls;
    use native_tls::TlsConnector;
    let connector = TlsConnector::new().unwrap();
    let greatlsstream = TcpStream::connect("sessionserver.mojang.com:443").unwrap();
    let mut tlsstream = connector
        .connect("sessionserver.mojang.com", greatlsstream)
        .unwrap();
    tlsstream.write_all(response.as_bytes()).unwrap();
    let mut buf = vec![];
    tlsstream.read_to_end(&mut buf).unwrap();
    let buf = String::from_utf8_lossy(&buf);
    let buf2: Vec<&str> = buf.split(" ").collect();
    match buf2[1] {
        "200" => {
            return "200".to_string();
        }
        code => {
            return code.to_string();
        }
    }
}