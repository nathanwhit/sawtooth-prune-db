#![allow(clippy::try_err)]

mod error;
mod ext;
mod merkle;
mod proto;
mod stopwatch;

use clap::Parser;
use color_eyre::eyre::Context;
use ext::*;

use color_eyre::Result;

use heed::flags::Flags;
use prost::Message;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;

use heed::{BytesDecode, BytesEncode, Database, EnvOpenOptions};

use crate::merkle::{Hash, MerkleDb, StateDatabase};

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

#[derive(Parser, Debug)]
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

    #[clap(
        short,
        long,
        about("force overwriting output database if it already exists")
    )]
    force: bool,

    output_db: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let opts = CliOpts::parse();

    let block_db_path = opts.data_dir.join(opts.block_db);
    let merkle_db_path = opts.data_dir.join(opts.merkle_db);
    let output_db_path = opts.output_db;

    if opts.force {
        fs_err::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_db_path)?;
    } else if let Err(err) = fs_err::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output_db_path)
    {
        match err.kind() {
                io::ErrorKind::AlreadyExists => Err(err).wrap_err_with(|| {
                    format!(
                        "the output database {:?} already exists. use a new path or pass '-f' to overwrite file",
                        output_db_path
                    )
                })?,
                _ => Err(err)?,
            }
    }

    if merkle_db_path.canonicalize()? == output_db_path.canonicalize()? {
        color_eyre::eyre::bail!("the output DB and merkle DB cannot be the same file!");
    }

    if std::env::var("RUST_LOG").is_err() {
        match opts.verbose {
            1 => std::env::set_var("RUST_LOG", "info"),
            2 => std::env::set_var("RUST_LOG", "debug"),
            3 => std::env::set_var("RUST_LOG", "trace"),
            _ => {}
        }
    }

    pretty_env_logger::init();

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

    let mut options = EnvOpenOptions::new();
    let fresh_state_env = unsafe {
        options
            .flag(Flags::MdbNoSubDir)
            .flag(Flags::MdbNoRdAhead)
            .flag(Flags::MdbMapAsync)
            .flag(Flags::MdbWriteMap)
            .flag(Flags::MdbNoLock)
            .max_dbs(3)
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

    let mut options = EnvOpenOptions::new();
    let block_env = unsafe {
        options
            .max_dbs(4)
            .flag(Flags::MdbNoSubDir)
            .flag(Flags::MdbRdOnly)
            .flag(Flags::MdbNoRdAhead)
            .flag(Flags::MdbNoLock)
            .flag(Flags::MdbNoSync)
            .flag(Flags::MdbNoMetaSync)
            .open(block_db_path)
            .wrap_err()?
    };
    let block_num_index: Database<heed::types::Str, merkle::HashEnc> = block_env
        .open_database(Some("index_block_num"))
        .wrap_err()?
        .unwrap();
    let block_db: Database<merkle::HashEnc, Protobuf<proto::Block>> =
        block_env.open_database(Some("main")).wrap_err()?.unwrap();
    let rtxn = block_env.read_txn().wrap_err()?;
    rtxn.commit().wrap_err()?;

    let mut state_hashes: indexmap::IndexSet<Hash, fxhash::FxBuildHasher> =
        indexmap::IndexSet::default();
    let rtxn = block_env.read_txn().wrap_err()?;
    let pb = indicatif::ProgressBar::new(block_db.len(&rtxn).wrap_err()?);
    log::info!("Collecting root nodes");
    for item in pb.wrap_iter(block_num_index.iter(&rtxn).wrap_err()?) {
        let (_block_num, hash) = item.wrap_err()?;
        let block = block_db.get(&rtxn, &hash).wrap_err()?.unwrap();
        let header: proto::BlockHeader = block.header.parse_into().unwrap();
        let hash: Hash = header.state_root_hash.try_into().unwrap();
        state_hashes.insert(hash);
    }
    rtxn.commit().wrap_err()?;

    let merkle = MerkleDb::new(state_env, &state_db)?;

    log::info!("Copying rooted trees to new database");

    merkle.copy_trees_to_db(state_hashes.into_iter().rev(), fresh_state_env, &fresh_db)?;

    Ok(())
}
