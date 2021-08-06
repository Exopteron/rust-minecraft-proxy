mod handler;
//use handler::User;
use handler::logging::logger;
use std::{net::{TcpListener}};
use rsa::{RSAPrivateKey};
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigFile {
    ip: Option<String>,
    port: u16,
    log_file: String,
}
fn main() -> std::io::Result<()> {
    let config = std::fs::read_to_string("conf.toml").unwrap();
    let config = toml::from_str::<ConfigFile>(&config);
    let config = match config {
        Err(_) => {
            panic!("Invalid configuration file!");
        } 
        Ok(file) => file
    };
    let mut ip = "0.0.0.0".to_owned();
    if config.ip.is_some() {
        ip = config.ip.unwrap();
    }
    let ip = format!("{}:{}", ip, config.port);
    let logger = logger::Logger::new(&config.log_file).unwrap();
    let listener = TcpListener::bind(&ip)?;
    logger.log_info("Generating RSA key, please wait")?;
    let key = generate_rsa_key();
    logger.log_info("Successfully generated RSA key")?;
    logger.log_info(&format!("Listening on {}", ip))?;
    //let users: Arc<Mutex<Vec<User>>> = Arc::new(Mutex::new(Vec::new()));
    for stream in listener.incoming() {
        let logger2 = logger.clone();
        let rsa_key = key.clone();
        std::thread::spawn(move || {
            let x = handler::Handler::from_stream(stream.unwrap(), logger2.clone(), rsa_key.clone());
            if x.is_err() {
                logger2.log_err(&format!("Error handling user: {}", x.err().unwrap())).unwrap();
            }
        });
    }
    Ok(())
}

fn generate_rsa_key() -> Arc<Mutex<RSAPrivateKey>> {
    let mut rng = OsRng;
    let private_key = RSAPrivateKey::new(&mut rng, 1024).unwrap();
    return Arc::new(Mutex::new(private_key));
}