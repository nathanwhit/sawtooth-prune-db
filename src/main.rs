#![allow(dead_code)]

mod database;
mod error;
mod hash;
mod merk;
mod merkle;
mod proto;
mod state;

use color_eyre::eyre::eyre;
use color_eyre::Result;
use core::fmt;
use database::lmdb::DatabaseReader;
use protobuf::Message;
use state::StateReader;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use heed::{BytesDecode, BytesEncode, Database, Env, EnvOpenOptions};

use crate::merkle::MerkleDatabase;

trait ResultExt: Sized {
    type Output;
    fn wrap_err(self) -> Self::Output;
}

impl<T> ResultExt for Result<T, heed::Error> {
    type Output = Result<T>;

    fn wrap_err(self) -> Self::Output {
        self.map_err(|err| eyre!(error::HeedError::new(err)))
    }
}

struct MerkleNode;

impl<'a> BytesEncode<'a> for MerkleNode {
    type EItem = merkle::Node;

    fn bytes_encode(
        item: &'a Self::EItem,
    ) -> Result<std::borrow::Cow<'a, [u8]>, Box<dyn StdError>> {
        let node = item.clone();
        Ok(node.into_bytes().map(Cow::Owned)?)
    }
}

impl<'a> BytesDecode<'a> for MerkleNode {
    type DItem = merkle::Node;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, Box<dyn StdError>> {
        let bytes: serde_cbor::value::Value = serde_cbor::from_slice(bytes)?;
        if let serde_cbor::value::Value::Bytes(bytes) = bytes {
            // println!("bytes = {:?}", bytes);
            Ok(merkle::Node::from_bytes(&bytes)?)
        } else {
            Err(eyre!("invalid type: expected bytes"))?
        }
    }
}

struct Protobuf<P>(PhantomData<P>);

impl<'a, P> BytesEncode<'a> for Protobuf<P>
where
    P: Message,
{
    type EItem = P;

    fn bytes_encode(item: &'a Self::EItem) -> Result<Cow<'a, [u8]>, Box<dyn StdError>> {
        Ok(item.write_to_bytes()?.into())
    }
}

impl<'a, P> BytesDecode<'a> for Protobuf<P>
where
    P: Message,
{
    type DItem = P;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, Box<dyn StdError>> {
        Ok(P::parse_from_bytes(bytes)?)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut options = EnvOpenOptions::new();
    let env = unsafe {
        options
            .max_dbs(4)
            .flag(heed::flags::Flags::MdbNoSubDir)
            .open("/home/nathanw/Downloads/_data/block-00.lmdb")
            .wrap_err()?
    };
    let block_num_index: Database<heed::types::Str, heed::types::Str> = env
        .open_database(Some("index_block_num"))
        .wrap_err()?
        .unwrap();
    let block_db: Database<heed::types::Str, Protobuf<proto::block::Block>> =
        env.open_database(Some("main")).wrap_err()?.unwrap();

    let rtxn = env.read_txn().wrap_err()?;
    let state_root = {
        let (k, v) = block_num_index.last(&rtxn).wrap_err()?.unwrap();
        let block = block_db.get(&rtxn, &v).wrap_err()?.unwrap();
        let header_bytes = block.get_header();
        let mut header = proto::block::BlockHeader::parse_from_bytes(&header_bytes)?;
        header.take_state_root_hash()
    };
    drop(rtxn);

    println!("main state root = {}", state_root);

    let mut options = EnvOpenOptions::new();

    let state_env_two = unsafe {
        options
            .flag(heed::flags::Flags::MdbNoSubDir)
            .flag(heed::flags::Flags::MdbRdOnly)
            .flag(heed::flags::Flags::MdbNoRdAhead)
            .flag(heed::flags::Flags::MdbNoLock)
            .flag(heed::flags::Flags::MdbNoSync)
            .flag(heed::flags::Flags::MdbNoMetaSync)
            .open("/home/nathanw/Downloads/_data/merkle-00.lmdb")
            .wrap_err()?
    };

    let state_db_two: Database<merk::HashEnc, merk::MerkNode> =
        state_env_two.open_database(None).wrap_err()?.unwrap();

    let state_node_count = state_db_two
        .len(&state_env_two.read_txn().wrap_err()?)
        .wrap_err()?;

    println!("state nodes: {}", state_node_count);

    let merkle_tree =
        merk::MerkleTree::new(state_env_two.clone(), &state_db_two, state_root.try_into()?)?;

    let mut tree_count = 0;

    merkle_tree.visit(|_| {
        tree_count += 1;
        if tree_count % 1000 == 0 {
            println!("{}", tree_count);
        }
    })?;

    println!("tree nodes: {}", tree_count);

    Ok(())
}
