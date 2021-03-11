#![feature(vec_into_raw_parts)]
extern crate libc;
extern crate nix;
extern crate openssl;
extern crate serde;
extern crate serde_json;

use libc::syscall;
use nix::fcntl::{self, OFlag};
use nix::sys::stat::Mode;
use nix::{ioctl_read, ioctl_readwrite};
use openssl::rsa::{Padding, Rsa};
use serde::Deserialize;
use sha2::{Digest, Sha512};
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
    const IMAGE_CONFIG_FILE: &str = "/etc/image_config.json";
    // const IMAGE_CONFIG_FILE: &str = "image_config.json";
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
            let rsa = Rsa::generate(2048).unwrap();
            let pubkey = rsa.public_key_to_pem().unwrap();

            // same for Sha512
            let mut hasher = Sha512::new();
            hasher.update(pubkey.clone());
            let result = hasher.finalize();

            let mut report_data = Box::new(SgxReportData {
                d: [0; SGX_REPORT_DATA_SIZE],
            });
            report_data.d.copy_from_slice(result.as_slice());

            println!("report_data {:?}", report_data);

            let sgx_file = fcntl::open("/dev/sgx", OFlag::O_RDONLY, Mode::S_IRWXU)
                .expect("can't read sgx device");

            // Get correct quote size
            let mut quote_size: u32 = 0;
            unsafe {
                get_quote_size(sgx_file, &mut quote_size).unwrap();
            }

            let quote_buf = vec![0 as u8; quote_size as usize];
            let (quote_buf_ptr, quote_buf_len, quote_buf_cap) = quote_buf.into_raw_parts();

            let quote_len = Box::new(quote_size);
            let mut quote = sgxioc_gen_dcap_quote_arg {
                report_data: Box::into_raw(report_data),
                quote_len: Box::into_raw(quote_len),
                quote_buf: quote_buf_ptr,
            };

            unsafe {
                gen_quote(sgx_file, &mut quote).unwrap();
            }

            let mut client = GreeterClient::connect("http://[::1]:50051").await?;
            let request = tonic::Request::new(HelloRequest {
                image_mac: image_config.occlum_json_mac,
                pubkey: pubkey,
                quote: unsafe { Vec::from_raw_parts(quote_buf_ptr, quote_buf_len, quote_buf_cap) },
            });

            let response = client.say_hello(request).await?;

            let mut image_key = vec![0 as u8; rsa.size() as usize];
            let image_key_size = rsa.private_decrypt(
                &response.get_ref().encrypted_key,
                &mut image_key,
                Padding::PKCS1,
            );

            image_key.resize_with(image_key_size.unwrap(), Default::default);

            let mut image_raw_key: sgx_key_128bit_t = Default::default();
            parse_str_to_bytes(std::str::from_utf8(&image_key).unwrap(), &mut image_raw_key)?;
            image_raw_key
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
    image_type: String,
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

pub const SGX_REPORT_DATA_SIZE: usize = 64;
#[derive(Debug)]
pub struct SgxReportData {
    pub d: [u8; SGX_REPORT_DATA_SIZE],
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
pub struct sgxioc_gen_dcap_quote_arg {
    pub report_data: *mut SgxReportData,
    pub quote_len: *mut u32,
    pub quote_buf: *mut u8,
}

// #define SGXIOC_GET_DCAP_QUOTE_SIZE _IOR('s', 7, uint32_t)
ioctl_read!(get_quote_size, b's', 7, u32);
// #define SGXIOC_GEN_DCAP_QUOTE _IOWR('s', 8, sgxioc_gen_dcap_quote_arg_t)
ioctl_readwrite!(gen_quote, b's', 8, sgxioc_gen_dcap_quote_arg);
