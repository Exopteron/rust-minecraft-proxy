#![allow(dead_code)]
use chrono::{DateTime, Local};
use std::io::Write;
#[derive(Clone)]
pub struct Logger {
    log_file: String,
}

impl Logger {
    pub fn new(logfile: &str) -> Result<Self, String> {
        std::fs::remove_file(logfile).unwrap();
        let now: DateTime<Local> = Local::now();
        if !std::path::Path::new(logfile).exists() {
            match std::fs::File::create(logfile) {
                Ok(_) => {
                    let ourselves = Self {
                        log_file: logfile.to_string(),
                    };
                    match ourselves.append_to_log(format!("Log file created at {}\n", now.to_rfc2822()).as_bytes()) {
                        Ok(_) => {
                            return Ok(ourselves);
                        }
                        Err(_) => {
                            return Err("Error!".to_string());
                        }
                    }
                }
                Err(_) => {
                    return Err("Error creating file!".to_string());
                }
            }
        }
        return Err("File exists!".to_string());
    }
    pub fn log_info(&self, log: &str) -> std::io::Result<()> {
        let now: DateTime<Local> = Local::now();
        let string = format!("[{} INFO] {}\n", now.format("%H:%M:%S"), log);
        std::io::stdout().write_all(string.as_bytes())?;
        self.append_to_log(string.as_bytes())?;
        Ok(())
    }
    pub fn log_err(&self, log: &str) -> std::io::Result<()> {
        let now: DateTime<Local> = Local::now();
        let string = format!("[{} ERROR] {}\n", now.format("%H:%M:%S"), log);
        std::io::stdout().write_all(string.as_bytes())?;
        self.append_to_log(string.as_bytes())?;
        Ok(())
    }
    pub fn log_warn(&self, log: &str) -> std::io::Result<()> {
        let now: DateTime<Local> = Local::now();
        let string = format!("[{} WARN] {}\n", now.format("%H:%M:%S"), log);
        std::io::stdout().write_all(string.as_bytes())?;
        self.append_to_log(string.as_bytes())?;
        Ok(())
    }
    pub fn log_debug(&self, log: &str) -> std::io::Result<()> {
        let now: DateTime<Local> = Local::now();
        let string = format!("[{} DEBUG] {}\n", now.format("%H:%M:%S"), log);
        std::io::stdout().write_all(string.as_bytes())?;
        self.append_to_log(string.as_bytes())?;
        Ok(())
    }
    fn append_to_log(&self, to_append: &[u8]) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&self.log_file)
            .unwrap();
        file.write_all(to_append)?;
        Ok(())
    }
}
