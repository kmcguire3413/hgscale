
extern crate byteorder;
extern crate crypto;
extern crate ws;
extern crate rand;
extern crate hgscale_common;

use std::sync::{Arc, Mutex, RwLock};
use std::result::Result;
use std::io::Cursor;
use hgscale_common::{Server, ServerCore, Packet, Client};

fn test_handler (server: &ServerCore, packet: Packet, client: Arc<Client>, was_secure: bool) {
	match packet {
		Packet::Unknown => (),
		Packet::GetOwnedEntities => {
			/*
				At the moment, we need to go through all the cubes; however, this
				could be optimized so that we held a data structure which could index
				all entities based on the user uid or user gid that was kept updated.

				uid - unique id (locally unique)
				gid - global id (globally unique) 

				A user is represented by a uid for the connection and a gid for the 
				actual user.
			*/
			let cubes = server.cubes.lock().unwrap();

			let client_gid;
			{
				// Lock quickly for read then unlock. Hopefully,
				// this was the best case for this kind of lock
				// since it should only ever be modified once.
				//
				// I might desire a custom type that can be changed
				// once, and then never again. 
				client_gid = *client.gid.read().unwrap();
			}

			let mut found: Vec<u64> = Vec::new();

			for c in cubes.iter() {
				let entities = c.entities.lock().unwrap();
				for e in entities.iter() {
					if e.gid == client_gid {
						found.push(e.uid);
					}
				}
			}

			{
				let sock = client.sender.lock().unwrap();
				sock.send((Packet::OwnedEntities { ids: found }).serialize().as_slice());
			}
		},
		Packet::GetEntityInfo { uid } => (),
		Packet::SendEntityMessage { uid, msg } => (),
		_ => (),
	}
}

fn main() {
	Server::run(test_handler, "0.0.0.0:10000");
}
