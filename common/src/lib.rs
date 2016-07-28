extern crate byteorder;
extern crate crypto;
extern crate ws;
extern crate rand;

use std::sync::{Arc, Mutex, RwLock};
use std::result::Result;
use std::io::Cursor;

pub struct CoreState {
	test: u8,
}

pub struct CoreHandler {
	state: Mutex<CoreState>,
}

macro_rules! err_exit {
	($e:expr) => (match $e {
		Result::Ok(val) => val,
		Result::Err(err) => return Option::None,
	});
}

pub enum CmdType {
	Unknown = 0,
	/*
		From: client
		To: cube

		See the cube contents.
	*/
	GetView = 1,
	/*
		From: client
		To: cube

		Get list of all owned entities.
	*/
	GetOwnedEntities = 2,
	/*
		From: client
		To: cube

		Get information on entity.
	*/
	GetEntityInfo = 3,
	/*
		From: client
		To: cube

		Send message to entity. The entities are self-contained logic, therefore, they
		can accept commands specific to them and apply their own rules and logic. The entity
		will utilize the shard framework to produce any needed tokens and handles honoring
		such tokens.
	*/
	SendEntityMessage = 4,
	/*
	*/
	GetCubeAddress = 5,

	OwnedEntities = 6,
	View = 7,
	EntityInfo = 8,

	RequestEntityMove = 9,

	X_SetUser = 10,
	X_StpComm = 11, // Setup communication (secure).
	X_StpCommRes = 12,
}

impl CmdType {
	fn from_value(val: u16) -> CmdType {
		if val == CmdType::GetView as u16 {
			return CmdType::GetView;
		}

		if val == CmdType::GetOwnedEntities as u16 {
			return CmdType::GetOwnedEntities;
		}

		if val == CmdType::GetEntityInfo as u16 {
			return CmdType::GetEntityInfo;
		}

		if val == CmdType::SendEntityMessage as u16 {
			return CmdType::SendEntityMessage;
		}

		if val == CmdType::GetCubeAddress as u16 {
			return CmdType::GetCubeAddress;
		}

		if val == CmdType::OwnedEntities as u16 {
			return CmdType::OwnedEntities;
		}

		if val == CmdType::View as u16 {
			return CmdType::View;
		}

		if val == CmdType::EntityInfo as u16 {
			return CmdType::EntityInfo;
		}

		if val == CmdType::RequestEntityMove as u16 {
			return CmdType::RequestEntityMove;
		}

		CmdType::Unknown
	}
}

pub struct Entity {
	pub uid:        u64,
	pub gid:        u64,
}

/*
	The graphic material is not used for game mechanics, however,
	it is needed to be handy to send to the client so that the
	world can be rendered for a human player.
*/
pub enum BlockGraphic {
	Nothing,
	SimpleMaterial { id: u16 }
}

/*
	128 total compositions

	8-composition attributes per block

	A 4-digit base 128.

	math.log(base^4 = max_needed_value, 2) = 56

	The world supports 128 different composition elements
	and each block can use at most 8 of them. One of the
	composition elements shall be known as nothing and a
	block may contain no compositin elements. All blocks
	contain some type of atmosphere, therefore, this allows
	the representation of air, water, mud, and other such
	things.

	The density of a block represents the ability of something
	to penetrate the block. This shall be a function of the
	mass of something. So that water will generally have a very
	low density allowing most things to sink or move through
	it and air of course will have the least; however, water
	would be slightly higher which will imbark a movement penalty
	on the something.

	Together the density allowing and restricting movement
	and the composition can enable an entity to be prohibited,
	injured, limited, or allowed to freely use a block.

	68 bytes per block
*/

pub struct Block {
	// The graphic for client side rendering. (visual only)
	pub graphic:		BlockGraphic,
	// If an entity resides here.
	pub euid:           Option<u64>,
	// The composition permutation.
	pub comp_per:       u64,
	// The actual composition.
	pub comp:           [f32; 8],
	pub density:        f32,
}

pub struct Cube {
	pub wx:         u64,
	pub wy:         u64,
	pub wz:         u64,
	pub entities: 	Mutex<Vec<Entity>>,
	pub blocks:     Mutex<Vec<Block>>,
}

/// The pertinent server object instance data. This is known as the core
/// and will generally be the desired reference to pass around for usage.
pub struct ServerCore {
	last_uid:		Mutex<u64>,
	pub cubes:          Mutex<Vec<Arc<Cube>>>,
}

/// The server object. It has a generic parameter denoting the type of
/// the handler function. This forms the basis of the extensibility and
/// reusage across.
pub struct Server<HANDLER> {
	core:           ServerCore,
	handler:        HANDLER,
}

/// Represents a client connection. It may represent an authenticated client
/// if the appropriate fields are properly set.
pub struct Client {
	pub sender:	Mutex<ws::Sender>,
	pub uid:    u64,
	pub gid:    RwLock<u64>,
}

pub enum EntityMoveDir {
	Up = 0,
	Down = 1,
	Left = 2,
	Right = 3,
	None = 4,
}

pub enum Packet {
	Unknown,
	GetView { cid: u64 },
	View,
	GetOwnedEntities,
	OwnedEntities { ids: Vec<u64> },
	GetEntityInfo { uid: u64 },
	EntityInfo { uid: u64 },
	SendEntityMessage { uid: u64, msg: Vec<u8> },
	RequestEntityMove { uid: u64, dir: EntityMoveDir },

	X_SetUser { gid: u64 },
	X_StpComm { xid: u64, cid: u64, gid: u64, uid: u64, wx: u64, wy: u64, wz: u64, seq: u64 },
	X_StpCommRes { xid: u64, seq: u64, accept: bool },

	X_HostCube { 
		cid: u64, 
		wx: u64, wy: u64, wz: u64, 
		blocks: Vec<Block>,
		entities: Vec<Entity>,
	},
}

impl Packet {
	pub fn encrypt_packet_buffer(buf: &[u8]) -> Vec<u8> {
		use crypto::aes::{KeySize, ctr};
		use crypto::sha2::Sha512;
		use crypto::digest::Digest;
		use rand::{Rng, OsRng};
		use std::iter::FromIterator;

		let key = vec![29, 84, 32, 45, 86, 45, 43, 23, 88, 92, 38, 129, 38, 234, 32, 43];
		let mut iv: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(16 as usize));
		let mut gen = OsRng::new().unwrap();
		let mut out: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(buf.len() + 16 + 64));
		let mut hash: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(64 as usize));

		// Hash the original message and store this hash as part of the new message.
		println!("hasing original packet");
		let mut hasher = Sha512::new();
		hasher.input(&buf[5 ..]);
		hasher.result(&mut hash);

		println!("generating initialization vector");
		gen.fill_bytes(iv.as_mut_slice());

		// Copy the IV into the output.
		for x in 0 .. 16 {
			out[x + 5] = iv[x];
		}

		// Encrypt only the message part using the provided key and IV, but skip
		// the header and the IV field. Make sure to encrypt the hash field as leaving
		// it unencrypted makes the protocol weaker.
		println!("encrypting packet");
		let mut cipher = ctr(KeySize::KeySize128, key.as_slice(), iv.as_slice());
		cipher.process(&hash, &mut out[5 + 16 .. 5 + 16 + 64]);
		cipher.process(&buf[5 ..], &mut out[5 + 16 + 64 ..]);

		// Copy size field needed and set the encrypted field to true.
		out[0] = 1u8;

		// Recalculate the actual payload size (minus headers) then add hash size
		// and rewrite.
		println!("rewriting packet header");
		let payload_sz = (buf.len() - 5) + 64;
		out[1] = ((payload_sz >> 0) & 0xff) as u8;
		out[2] = ((payload_sz >> 8) & 0xff) as u8;
		out[3] = ((payload_sz >> 16) & 0xff) as u8;
		out[4] = ((payload_sz >> 24) & 0xff) as u8;

		out
	}

	pub fn decrypt_packet_buffer(buf: &[u8]) -> Option<Vec<u8>> {
		use crypto::aes::{KeySize, ctr};
		use crypto::sha2::Sha512;
		use crypto::digest::Digest;
		use rand::{Rng, OsRng};
		use std::iter::FromIterator;
		use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
		use std::io::{Cursor, Read};

		let mut buf_cur = Cursor::new(buf);

		let key = vec![29, 84, 32, 45, 86, 45, 43, 23, 88, 92, 38, 129, 38, 234, 32, 43];
		let mut iv: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(16 as usize));
		let mut hash: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(64 as usize));
		let mut rhash: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(64 as usize));

		if buf.len() < 16 + 64 {
			return Option::None;
		}

		let mut out: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(buf.len() - 16 - 64));

		match buf_cur.read_exact(&mut iv) { Result::Err(_) => return Option::None, Result::Ok(_) => () };

		// Decrypt the hash and store it.
		let mut cipher = ctr(KeySize::KeySize128, key.as_slice(), iv.as_slice());
		cipher.process(&buf[16 .. 16 + 64], hash.as_mut_slice());

		// Decrypt the remaining packet.
		cipher.process(&buf[16 + 64 ..], out.as_mut_slice());

		// Check hash.
		println!("generating hash of decrypted bytes");
		let mut hasher = Sha512::new();
		hasher.input(out.as_slice());
		hasher.result(rhash.as_mut_slice());

		for x in 0 .. hash.len() {
			if hash[x] != rhash[x] {
				println!("decryption hash validation failed");
				return Option::None;
			}
		}

		println!("decryption hash validation was good");

		Option::Some(out)
	}

	pub fn serialize(&self) -> Vec<u8> {
		use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
		use std::io::Write;

		let mut buf: Vec<u8> = Vec::new();

		// Write the encrypted flag and the size as zeros for now.
		buf.push(0);
		buf.push(0);
		buf.push(0);
		buf.push(0);
		buf.push(0);
		
		match self {
			&Packet::Unknown => {
				buf.write_u16::<LittleEndian>(CmdType::Unknown as u16);
			},
			&Packet::GetView { cid } => {
				buf.write_u16::<LittleEndian>(CmdType::GetView as u16);
				buf.write_u64::<LittleEndian>(cid);
			},
			&Packet::View => {
				buf.write_u16::<LittleEndian>(CmdType::View as u16);
			},
			&Packet::GetOwnedEntities => {
				buf.write_u16::<LittleEndian>(CmdType::GetOwnedEntities as u16);
			},
			&Packet::OwnedEntities { ref ids } => {
				buf.write_u16::<LittleEndian>(CmdType::OwnedEntities as u16);
				for id in ids.iter() {
					buf.write_u64::<LittleEndian>(*id);
				}
			},
			&Packet::GetEntityInfo { uid } => {
				buf.write_u16::<LittleEndian>(CmdType::GetEntityInfo as u16);
				buf.write_u64::<LittleEndian>(uid);				
			},
			&Packet::EntityInfo { uid } => {
				buf.write_u16::<LittleEndian>(CmdType::EntityInfo as u16);
				buf.write_u64::<LittleEndian>(uid);
			},
			&Packet::SendEntityMessage { uid, ref msg } => {
				buf.write_u16::<LittleEndian>(CmdType::SendEntityMessage as u16);
				buf.write_u64::<LittleEndian>(uid);
				buf.write(msg.as_slice());
			},
			&Packet::RequestEntityMove { uid, ref dir } => {
				buf.write_u16::<LittleEndian>(CmdType::RequestEntityMove as u16);
				buf.write_u64::<LittleEndian>(uid);
				match dir {
					&EntityMoveDir::Up => buf.write_u8(EntityMoveDir::Up as u8),
					&EntityMoveDir::Down => buf.write_u8(EntityMoveDir::Down as u8),
					&EntityMoveDir::Left => buf.write_u8(EntityMoveDir::Left as u8),
					&EntityMoveDir::Right => buf.write_u8(EntityMoveDir::Right as u8),
					&EntityMoveDir::None => buf.write_u8(EntityMoveDir::None as u8),
				};
			}
			&Packet::X_SetUser { gid } => {
				buf.write_u16::<LittleEndian>(CmdType::X_SetUser as u16);
				buf.write_u64::<LittleEndian>(gid);
			},
			&Packet::X_StpComm { xid, cid, gid, uid, wx, wy, wz, seq } => {
				buf.write_u16::<LittleEndian>(CmdType::X_StpComm as u16);
				buf.write_u64::<LittleEndian>(xid);
				buf.write_u64::<LittleEndian>(cid);
				buf.write_u64::<LittleEndian>(gid);
				buf.write_u64::<LittleEndian>(uid);
				buf.write_u64::<LittleEndian>(wx);
				buf.write_u64::<LittleEndian>(wy);
				buf.write_u64::<LittleEndian>(wz);
				buf.write_u64::<LittleEndian>(seq);
			},
			&Packet::X_StpCommRes { xid, seq, accept } => {
				buf.write_u16::<LittleEndian>(CmdType::X_StpCommRes as u16);
				buf.write_u64::<LittleEndian>(xid);
				buf.write_u64::<LittleEndian>(seq);
				buf.write_u8(match accept { true => 1, false => 0 });
			},
			&Packet::X_HostCube { cid, wx, wy, wz, ref blocks, ref entities } => {
				panic!("Not implemented");
			},
		}

		// Write the size out as a 32-bit little endian.
		let payload_sz = buf.len() - 5;
		buf[1] = ((payload_sz >> 0) & 0xff) as u8;
		buf[2] = ((payload_sz >> 8) & 0xff) as u8;
		buf[3] = ((payload_sz >> 16) & 0xff) as u8;
		buf[4] = ((payload_sz >> 24) & 0xff) as u8;

		buf
	}

	pub fn decode(cmd_raw: &[u8]) -> Packet {
		macro_rules! err_exit {
			($e:expr) => (match $e {
				Result::Ok(val) => val,
				Result::Err(err) => return Packet::Unknown,
			});
		}

		use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
		use std::io::{Cursor, Read};

		let cmd_raw_sz = cmd_raw.len();

		let mut cmd_cur = Cursor::new(cmd_raw);

		let cmd_type = match cmd_cur.read_u16::<LittleEndian>() { Result::Err(_) => return Packet::Unknown, Result::Ok(t) => t };
		println!("cmd_type:{}", cmd_type);
		match cmd_type {
			cmd_type if cmd_type == CmdType::GetView as u16 => {
				let cid = match cmd_cur.read_u64::<LittleEndian>() { Result::Err(_) => return Packet::Unknown, Result::Ok(t) => t };
				Packet::GetView { cid: cid }
			},
			cmd_type if cmd_type == CmdType::GetOwnedEntities as u16 => {
				panic!("Need implementation.");
			},
			cmd_type if cmd_type == CmdType::GetEntityInfo as u16 => {
				let uid = match cmd_cur.read_u64::<LittleEndian>() { Result::Err(_) => return Packet::Unknown, Result::Ok(t) => t };
				Packet::EntityInfo { uid: uid }
			},
			cmd_type if cmd_type == CmdType::SendEntityMessage as u16 => {
				let uid = match cmd_cur.read_u64::<LittleEndian>() { Result::Err(_) => return Packet::Unknown, Result::Ok(t) => t };
				let mut msg: Vec<u8> = Vec::with_capacity(cmd_raw_sz - cmd_cur.position() as usize);

				cmd_cur.read_exact(msg.as_mut_slice());

				Packet::SendEntityMessage { uid: uid, msg: msg }
			},
			cmd_type if cmd_type == CmdType::RequestEntityMove as u16 => {
				let uid = match cmd_cur.read_u64::<LittleEndian>() { Result::Err(_) => return Packet::Unknown, Result::Ok(t) => t };
				let dir = match cmd_cur.read_u8() { 
					Result::Err(_) => return Packet::Unknown, 
					Result::Ok(v) => {
						match v {
							0 => EntityMoveDir::Up,
							1 => EntityMoveDir::Down,
							2 => EntityMoveDir::Left,
							3 => EntityMoveDir::Right,
							_ => EntityMoveDir::None,
						}
					}, 
				};

				Packet::RequestEntityMove { uid: uid, dir: dir }
			},
			cmd_type if cmd_type == CmdType::X_SetUser as u16 => {
				let gid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				Packet::X_SetUser { gid: gid }
			},
			cmd_type if cmd_type == CmdType::X_StpComm as u16 => {
				let xid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let cid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let gid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let uid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let wx = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let wy = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let wz = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let seq = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				Packet::X_StpComm { xid: xid, gid: gid, cid: cid, uid: uid, wx: wx, wy: wy, wz: wz, seq: seq }
			},
			cmd_type if cmd_type == CmdType::X_StpCommRes as u16 => {
				let xid = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let seq = err_exit!(cmd_cur.read_u64::<LittleEndian>());
				let accept = match err_exit!(cmd_cur.read_u8()) {
					0 => false,
					1 => true,
					_ => false,
				};
				Packet::X_StpCommRes { xid: xid, seq: seq, accept: accept }
			}
			cmd_type if cmd_type == CmdType::Unknown as u16 => {
				Packet::Unknown
			},
			_ => {
				if cfg!(debug_assertions = "true") {
					// For a debug build it is desired for it to crash to get the
					// attention of the developer.
					panic!("The packet is unknown. This panic is caused by a debug build.")
				}

				// In production this could be from a malicious or malfunctioning client, 
				// therefore, just return an unknown packet type.

				Packet::Unknown
			}
		}
	}
}

#[cfg(all(test))]
mod PacketTest {
	use super::Packet;

	#[test]
	pub fn packet_types() {
		let a = Packet::X_StpComm { xid: 483, uid: 82732, cid: 324, gid: 983, wx: 3432, wy: 8745, wz: 8234, seq: 8372 };
		let b = a.serialize();
		// Drop the header which is created by serialize.
		let c = Packet::decode(&b[5..]);

		match c {
			Packet::X_StpComm { xid, cid, gid, wx, wy, wz, seq, uid } => {
				if xid != 483 || cid != 324 || gid != 983 || 
				   wx != 3432 || wy != 8745 || wz != 8234 || 
				   seq != 8372 || uid != 82732 {
				   	panic!("The packet did not deserialize correctly.");
				}
			},
			_ => panic!("The packet did not deserialize into the correct type.")
		}

		// Add more...
	}

	#[test]
	pub fn packet_secure_crypt() {
		/*
			Test that the packet encryption and decryption routines
			work as needed. The two routines are not symmetrical in
			the input needed. The encryption routine expects a valid
			packet header. The decryption routine does not expect a
			packet header and its output only contain the payload.

			This asymetry is done for performance reasons.
		*/
		use rand::{Rng, OsRng};
		use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
		use std::io::{Cursor, Read};
		use std::iter::FromIterator;
		use std::iter::repeat;

		for z in 0..100 {
			let mut plain: Vec<u8> = Vec::from_iter(repeat(0u8).take(1024 as usize));

			{
				let mut c = Cursor::new(plain);
				c.write_u8(0);
				c.write_u32::<LittleEndian>(1024 - 5);
				plain = c.into_inner();
			}

			println!("encrypting");
			let crypt = Packet::encrypt_packet_buffer(&plain);

			// Do this quick check. It is a simple and costly mistake.
			if crypt[0] != 1 {
				panic!("The encrypted packet did not have the proper first byte.")
			}

			println!("decrypting");
			let plain2 = Packet::decrypt_packet_buffer(&crypt[5..]).unwrap();

			for x in 0..plain2.len() {
				if plain[x + 5] != plain2[x] {
					panic!("The decrypted packet was not equal to the encrypted packet.");
				}
			}
		}
	}
}

impl<HANDLER> Server<HANDLER> where 
	HANDLER: 'static + Fn(&ServerCore, Packet, Arc<Client>, bool)
	{
	
	/// Routes decoded packet from client to a handler.
	fn handle_cmd_raw(&self, cmd_raw: Vec<u8>, client: Arc<Client>, was_secure: bool) {
		let packet = Packet::decode(&cmd_raw);

		(self.handler)(&self.core, packet, client, was_secure);
	}

	/// Returns a new identifier that is unique to this server object instance.
	fn get_new_uid(&self) -> u64 {
		let mut last_uid = self.core.last_uid.lock().unwrap();

		*last_uid += 1;

		*last_uid
	}

	/// Handles a message provided by a client.
	fn handle_message(&self, mut msg: Vec<u8>, client: Arc<Client>) {
		use std::io::{Write, Read};
		use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
		use crypto::aes::{KeySize, ctr};
		use std::iter::FromIterator;

		/*
			We need authorization data. This tells us what this client is authorized to access. This
			message is time sensitive. This means that the authentication server must renew this message
			after a certain amount of time. The client is also provided with these details.
		*/
		let mut msg_cursor = Cursor::new(msg);

		/*
			At this point, the client can provide commands.

			First (1) read the number of commands, then for each command (2) read the token, and (3) for
			each command read the command, (4) parse the token and command, and (5) finally execute the
			command.
		*/
		match msg_cursor.read_u16::<LittleEndian>() {
			Result::Err(_) => return,
			Result::Ok(cmd_cnt) => {
				for cmd_ndx in 0..cmd_cnt {
					let encrypted = match msg_cursor.read_u8() { Result::Err(_) => return, Result::Ok(v) => v };
					let cmd_sz = match msg_cursor.read_u32::<LittleEndian>() { Result::Err(_) => return, Result::Ok(v) => v };
					let mut cmd_buf: Vec<u8> = Vec::from_iter(std::iter::repeat(0u8).take(cmd_sz as usize));
					match msg_cursor.read_exact(&mut cmd_buf) {
						Result::Err(_) => break,
						Result::Ok(_) => (),
					};

					if encrypted == 1 {
						match Packet::decrypt_packet_buffer(&cmd_buf) {
							Option::None => break,
							Option::Some(cmd_buf_decrypted) => self.handle_cmd_raw(cmd_buf_decrypted, client.clone(), true),
						};
					} else {
						self.handle_cmd_raw(cmd_buf, client.clone(), false);
					}
				}
			}
		}
	}

	/// Initializes a new server object, but not _not_ run the server.
	fn new(handler: HANDLER) -> Server<HANDLER> {
		Server {
			core: ServerCore { 
				last_uid: Mutex::new(1000),
				cubes: Mutex::new(Vec::new()),
			},
			handler: handler,
		}
	}

	/// Runs the server by listening on a port and does _not_ return control back.
	pub fn run(handler: HANDLER, addr: &str) {
		let mut clients: Vec<Arc<Client>> = Vec::new();
		let server = Arc::new(Server::new(handler));

		ws::listen(addr, |out| {
			let server_clone = server.clone();

			let client = Arc::new(Client { 
				sender: Mutex::new(out), 
				uid: server_clone.get_new_uid(),
				gid: RwLock::new(0),
			});

			clients.push(client.clone());

			move |msg: ws::Message| {
				server_clone.handle_message(msg.into_data(), client.clone());
				Result::Ok(()) 
			}
		});
	}
}