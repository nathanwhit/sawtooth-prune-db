mod error;
mod ext;
mod merkle;
mod proto;

use clap::Parser;
use ext::*;

use color_eyre::Result;

use heed::flags::Flags;
use prost::Message;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use heed::{BytesDecode, BytesEncode, Database, EnvOpenOptions};

use crate::merkle::{Hash, StateDatabase};

struct Protobuf<P>(PhantomData<P>);

impl<'a, P> BytesEncode<'a> for Protobuf<P>
where
    P: Message + Default + 'a,
{
    type EItem = P;

    fn bytes_encode(item: &'a Self::EItem) -> Result<Cow<'a, [u8]>, Box<dyn StdError>> {
        Ok(item.to_bytes().into())
    }
}

impl<'a, P> BytesDecode<'a> for Protobuf<P>
where
    P: Message + Default + 'a,
{
    type DItem = P;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, Box<dyn StdError>> {
        Ok(P::try_parse(bytes)?)
    }
}

fn get_main_state_root<P: AsRef<Path>>(block_db_path: P) -> Result<Hash> {
    let mut options = EnvOpenOptions::new();
    let env = unsafe {
        options
            .max_dbs(4)
            .flag(Flags::MdbNoSubDir)
            .open(block_db_path)
            .wrap_err()?
    };
    let block_num_index: Database<heed::types::Str, heed::types::Str> = env
        .open_database(Some("index_block_num"))
        .wrap_err()?
        .unwrap();
    let block_db: Database<heed::types::Str, Protobuf<proto::Block>> =
        env.open_database(Some("main")).wrap_err()?.unwrap();
    let rtxn = env.read_txn().wrap_err()?;
    let state_root = {
        let (_k, v) = block_num_index.last(&rtxn).wrap_err()?.unwrap();
        let block = block_db.get(&rtxn, &v).wrap_err()?.unwrap();
        let header = proto::BlockHeader::try_parse(&block.header)?;
        header.state_root_hash
    };
    rtxn.commit().wrap_err()?;
    state_root.try_into()
}

#[derive(Parser)]
pub struct CliOpts {
    data_dir: PathBuf,

    #[clap(
        short,
        parse(from_occurrences),
        about("Set verbosity of logging output")
    )]
    verbose: u32,

    #[clap(short, long, default_value = "merkle-00.lmdb")]
    merkle_db: PathBuf,

    #[clap(short, long, default_value = "block-00.lmdb")]
    block_db: PathBuf,

    output_db: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let opts = CliOpts::parse();

    let block_db_path = opts.data_dir.join(opts.block_db);
    let merkle_db_path = opts.data_dir.join(opts.merkle_db);
    let output_db_path = opts.output_db;

    if std::env::var("RUST_LOG").is_err() {
        match opts.verbose {
            1 => std::env::set_var("RUST_LOG", "info"),
            2 => std::env::set_var("RUST_LOG", "debug"),
            3 => std::env::set_var("RUST_LOG", "trace"),
            _ => {}
        }
    }

    pretty_env_logger::init();

    let state_root = get_main_state_root(&block_db_path)?;

    let mut options = EnvOpenOptions::new();

    let state_env = unsafe {
        options
            .flag(Flags::MdbNoSubDir)
            .flag(Flags::MdbRdOnly)
            .flag(Flags::MdbNoRdAhead)
            .flag(Flags::MdbNoLock)
            .flag(Flags::MdbNoSync)
            .flag(Flags::MdbNoMetaSync)
            .open(merkle_db_path)
            .wrap_err()?
    };

    let state_db: StateDatabase = state_env.open_database(None).wrap_err()?.unwrap();

    let merkle_tree = merkle::MerkleTree::new(state_env.clone(), &state_db, state_root)?;

    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output_db_path)?;

    let mut options = EnvOpenOptions::new();
    let fresh_state_env = unsafe {
        options
            .flag(Flags::MdbNoSubDir)
            .flag(Flags::MdbNoRdAhead)
            .flag(Flags::MdbMapAsync)
            .flag(Flags::MdbNoMetaSync)
            .flag(Flags::MdbWriteMap)
            .flag(Flags::MdbNoLock)
            .map_size(1024usize.pow(4))
            .open(&output_db_path)
            .wrap_err()?
    };

    let fresh_db: StateDatabase = {
        match fresh_state_env.open_database(None).wrap_err()? {
            Some(db) => db,
            None => fresh_state_env.create_database(None).wrap_err()?,
        }
    };

    merkle_tree.copy_to_db(fresh_state_env.clone(), &fresh_db)?;

    Ok(())
}
