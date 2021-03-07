extern crate libc;
extern crate serde;
extern crate serde_json;

use libc::syscall;
use serde::Deserialize;

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;

use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the configuration from initfs
    const IMAGE_CONFIG_FILE: &str = "image_config.json";
    let image_config = load_config(IMAGE_CONFIG_FILE)?;

    // Get the MAC of Occlum.json.protected file
    let occlum_json_mac = {
        let mut mac: sgx_aes_gcm_128bit_tag_t = Default::default();
        parse_str_to_bytes(&image_config.occlum_json_mac, &mut mac)?;
        mac
    };
    let occlum_json_mac_ptr = &occlum_json_mac as *const sgx_aes_gcm_128bit_tag_t;

    // Get the key of encrypted SEFS image if exists
    let key = match image_config.key {
        Some(key_str) => {
            let mut key: sgx_key_128bit_t = Default::default();
            parse_str_to_bytes(&key_str, &mut key)?;
            key
        }
        None => {
            let mut client = GreeterClient::connect("http://[::1]:50051").await?;

            let request = tonic::Request::new(HelloRequest {
                name: image_config.occlum_json_mac,
            });

            let response = client.say_hello(request).await?;

            println!("key={:?}", response.get_ref().message);
            let mut key: sgx_key_128bit_t = Default::default();
            parse_str_to_bytes(&response.get_ref().message, &mut key)?;
            key
        }
    };

    let key_ptr = &key as *const sgx_key_128bit_t;

    // Mount the image
    const SYS_MOUNT_FS: i64 = 363;
    let ret = unsafe { syscall(SYS_MOUNT_FS, key_ptr, occlum_json_mac_ptr) };
    if ret < 0 {
        return Err(Box::new(InitError("SYS_MOUNT_FS Error...")) as Box<dyn std::error::Error>);
    }

    Ok(())
}

#[allow(non_camel_case_types)]
type sgx_key_128bit_t = [u8; 16];
#[allow(non_camel_case_types)]
type sgx_aes_gcm_128bit_tag_t = [u8; 16];

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ImageConfig {
    occlum_json_mac: String,
    #[serde(default)]
    key: Option<String>,
}

fn load_config(config_path: &str) -> Result<ImageConfig, Box<dyn std::error::Error>> {
    let mut config_file = File::open(config_path)?;
    let config_json = {
        let mut config_json = String::new();
        config_file.read_to_string(&mut config_json)?;
        config_json
    };
    let config: ImageConfig = serde_json::from_str(&config_json)?;
    Ok(config)
}

fn parse_str_to_bytes(arg_str: &str, bytes: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let bytes_str_vec = {
        let bytes_str_vec: Vec<&str> = arg_str.split('-').collect();
        if bytes_str_vec.len() != bytes.len() {
            return Err(Box::new(InitError(
                "The length or format of Key/MAC string is invalid",
            )) as Box<dyn std::error::Error>);
        }
        bytes_str_vec
    };

    for (byte_i, byte_str) in bytes_str_vec.iter().enumerate() {
        bytes[byte_i] = u8::from_str_radix(byte_str, 16)?;
    }
    Ok(())
}

#[derive(Debug)]
struct InitError<'a>(&'a str);

// Error doesn't require you to implement any methods, but
// your type must also implement Debug and Display.
impl<'a> Error for InitError<'a> {}

impl<'a> fmt::Display for InitError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the Display impl for `&str`:
        self.0.fmt(f)
    }
}
