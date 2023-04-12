use actix_web::{get,post, web, App, HttpResponse, HttpServer, Responder, error};
use clap::Parser;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::task;
use serde_json;
extern crate kademlia_dht;
use kademlia_dht::node::Node;
use kademlia_dht::protocol::Protocol;
use kademlia_dht::utils;
use kademlia_dht::utils::Args;


const MAX_SIZE: usize = 262_144;


#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    log_block_number:i32,
    log_index: i32,
    log_name: String,
    from: String,
    to: String,
    tokens: String
}

// #[derive(Serialize, Deserialize, Debug)]
// struct PayLod{
//     payload : web::Payload
// }
// impl PayLod for web::Payload {

// }

#[get("/node")]
async fn events(node: web::Data<Node>) -> impl Responder {
    // let event =  Event {
    //     log_block_number:1,
    //     log_index:1,
    //     log_name: String::from("Transfer"),
    //     from: String::from("0xBA826fEc90CEFdf6706858E5FbaFcb27A290Fbe0"),
    //     to: String::from("0x4aEE792A88eDDA29932254099b9d1e06D537883f"),
    //     tokens: String::from("2863452144424379687066"),
    // };

    // let serialized = serde_json::to_string(&event).unwrap();
    // println!("serialized = {}", serialized);

    match serde_json::to_string(&node) {
        Ok(response_str) => response_str,
        Err(_) => "data Error".to_string(),
    }
}

#[post("/node")]
async fn nodeping(mut payload: web::Payload, node: web::Data<Node>, interface: web::Data<Protocol> ) -> impl Responder {
   
    // let event =  Event {
    //     log_block_number:1,
    //     log_index:1,
    //     log_name: String::from("Transfer"),
    //     from: String::from("0xBA826fEc90CEFdf6706858E5FbaFcb27A290Fbe0"),
    //     to: String::from("0x4aEE792A88eDDA29932254099b9d1e06D537883f"),
    //     tokens: String::from("2863452144424379687066"),
    // };

    // let serialized = serde_json::to_string(&event).unwrap();
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }
    println!("[+] Created node0: {:?}", body);
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<Node>(&body)?;
    println!("[+] deserialized node0: {:?}", obj);
    let key = String::from("node");
    let val = String::from("node");
    let calu = interface.ping(obj.clone());
    // interface.store(obj.clone(), key.clone(), format!("{}{}", val, obj.port.to_string()));
    
    // utils::dump_interface_state(&interface, "dumps/interface0.json");



    // let value = interface.value_lookup(key);
    println!("[+] node distance node0: {:?}", calu);
    Ok(HttpResponse::Ok().json(obj)) 

    // match serde_json::to_string(&node) {
    //     Ok(response_str) => response_str,
    //     Err(_) => "data Error".to_string(),
    // }
}

#[get("/")]
async fn echo() -> impl Responder {
    HttpResponse::Ok().body("server is live")
}

pub async fn start_server(node:Node) -> Result<(), std::io::Error> {
    let args = Args::parse();
    let ip = node.ip.clone();
    let port = node.port.clone();
    println!("{:?}:{:?} server start up ", ip, port);
    println!("{:?}:{:?} node start up ", node.ip, node.port);
    let interface = Protocol::new(node.ip.clone(), node.port.clone(), None);
    interface.put("some_key".to_owned(), "some_value".to_owned());
    let server = HttpServer::new(move || {
        App::new()
        .app_data(web::Data::new(node.clone()))
        .app_data(web::Data::new(interface.clone()))
        .service(events)
        .service(nodeping)
            .service(echo)
        })
        .bind((ip, port))?
        .run();
    server.await.unwrap();
    Ok(())
}
