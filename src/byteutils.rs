pub struct ByteUtil {

}
pub enum Packet {
    PacketHandshakeC2S {usernameandhost: String}
}
impl ByteUtil {
    pub fn parse_packet(stream: &mut dyn std::io::Read, state: u8, client: bool) -> Option<Packet> {
        let id = Self::read_byte(stream).unwrap();
        match id {
            0x02 => {
                if state == 0 && client == true {
                    let string = Self::read_string(stream);
                    match string {
                        Some(string) => {
                            return Some(Packet::PacketHandshakeC2S {usernameandhost: string});
                        }
                        None => {
                            return None;
                        }
                    }
                }
            }
            _ => {
                println!("Lol");
            }
        }
        return None;
    }
    pub fn write_spawn_position(stream: &mut dyn std::io::Write, x: i32, y: i32, z: i32) -> Option<()> {
        let mut packet = vec![];
        packet.push(0x06);
        packet.append(&mut Self::write_int(x));
        packet.append(&mut Self::write_int(y));
        packet.append(&mut Self::write_int(z));
        let isok = stream.write(&packet);
        match isok {
            Ok(_) => {
                return Some(());
            }
            Err(_) => {
                return None;
            }
        }
    }
    pub fn write_disconnect(stream: &mut dyn std::io::Write, reason: &str) -> Option<()> {
        let mut packet = vec![];
        packet.push(0xFF);
        packet.append(&mut Self::write_string(reason.to_string()));
        stream.write(&packet).unwrap();
        Some(())
    }
    pub fn write_ppal_s2c(stream: &mut dyn std::io::Write, x: f64, y: f64, z: f64, stance: f64, yaw: f32, pitch: f32, onground: bool) -> Option<()> {
        let mut packet = vec![];
        packet.push(0x0D);
        packet.append(&mut Self::write_double(x));
        packet.append(&mut Self::write_double(stance));
        packet.append(&mut Self::write_double(y));
        packet.append(&mut Self::write_double(z));
        packet.append(&mut Self::write_float(yaw));
        packet.append(&mut Self::write_float(pitch));
        match onground {
            false => {
                packet.push(0x00);
            }
            true => {
                packet.push(0x01);
            }
        }
        let isok = stream.write(&packet);
        match isok {
            Ok(_) => {
                return Some(());
            }
            Err(_) => {
                return None;
            }
        }
    }
    fn read_byte(stream: &mut dyn std::io::Read) -> Option<u8> {
        let mut id = [0; 1];
        let isread = stream.read_exact(&mut id);
        match isread {
            Ok(()) => {
                return Some(id[0]);
            }
            Err(_) => {
                return None;
            }
        }
    }
    fn read_string(stream: &mut dyn std::io::Read) -> Option<String> {
        let len = Self::read_short(stream);
        match len {
            Some(num) => {
                let bytes = Self::read_bytes(stream, num as usize * 2);
                match bytes {
                    Some(bytes) => {
                        return Some(String::from_utf8_lossy(&bytes).to_string());
                    }
                    None => {
                        return None;
                    }
                }
            }
            None => {
                return None;
            }
        }
    }
    pub fn write_string(string: String) -> Vec<u8> {
        let mut vec = vec![];
        vec.append(&mut Self::write_short(string.len() as i16));
        let string = string.as_bytes().to_vec();
        for byte in string {
            vec.push(0x00);
            vec.push(byte);
        }
        //vec.append(&mut string.as_bytes().to_vec());
        return vec;
    }
    fn read_bytes(stream: &mut dyn std::io::Read, amount: usize) -> Option<Vec<u8>> {
        let mut id = vec![0; amount];
        let isread = stream.read_exact(&mut id);
        match isread {
            Ok(()) => {
                return Some(id);
            }
            Err(_) => {
                return None;
            }
        }
    }
    fn read_short(stream: &mut dyn std::io::Read) -> Option<i16> {
        let mut id = [0; 2];
        let isread = stream.read_exact(&mut id);
        match isread {
            Ok(()) => {
                return Some(i16::from_be_bytes(id));
            }
            Err(_) => {
                return None;
            }
        }
    }
    pub fn read_int(stream: &mut dyn std::io::Read) -> Option<i32> {
        let mut id = [0; 4];
        let isread = stream.read_exact(&mut id);
        match isread {
            Ok(()) => {
                return Some(i32::from_be_bytes(id));
            }
            Err(_) => {
                return None;
            }
        }
    }
    fn write_short(num: i16) -> Vec<u8> {
        return num.to_be_bytes().to_vec();
    }
    fn write_int(num: i32) -> Vec<u8> {
        return num.to_be_bytes().to_vec();
    }
    fn write_float(num: f32) -> Vec<u8> {
        return num.to_be_bytes().to_vec();
    }
    fn write_double(num: f64) -> Vec<u8> {
        return num.to_be_bytes().to_vec();
    }
}