extern crate openssl;

use openssl::rsa::{Padding, Rsa};
use tonic::{transport::Server, Request, Response, Status};

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request.get_ref().name);

        let rsa = Rsa::public_key_from_pem(&request.get_ref().pubkey).unwrap();

        let data: Vec<u8> =
            String::from("ff-2a-f9-29-ce-6d-95-04-93-70-6e-83-64-1b-d6-0c").into_bytes();
        let mut encrypted_key: Vec<u8> = vec![0; rsa.size() as usize];
        let encrypted_key_size = rsa
            .public_encrypt(&data, encrypted_key.as_mut_slice(), Padding::PKCS1)
            .unwrap();

        encrypted_key.resize_with(encrypted_key_size, Default::default);

        let reply = hello_world::HelloReply {
            encrypted_key: encrypted_key,
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let greeter = MyGreeter::default();

    Server::builder()
        .add_service(GreeterServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}
