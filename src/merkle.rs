use color_eyre::{Report, Result};
use core::fmt;
use derive_more::{From, Into};
use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
    error::Error as StdError,
    sync::{atomic::AtomicU64, Mutex},
};

use heed::{BytesDecode, BytesEncode, RoTxn};
use serde::{Deserialize, Serialize};

use crate::ext::*;

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node {
    #[serde(rename = "c")]
    children: BTreeMap<Token, Hash>,
    #[serde(rename = "v")]
    #[serde(with = "serde_bytes")]
    value: Option<Vec<u8>>,
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("children", &self.children)
            .field("value", &self.value)
            .finish()
    }
}

impl Node {
    pub fn from_bytes<B>(bytes: B) -> Result<Self>
    where
        B: AsRef<[u8]>,
    {
        let bytes: &serde_bytes::Bytes = serde_cbor::from_slice(bytes.as_ref())?;
        Ok(serde_cbor::from_slice(bytes)?)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Hash(pub String);

impl TryFrom<String> for Hash {
    type Error = Report;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !value.as_bytes().into_iter().all(u8::is_ascii_hexdigit) {
            Err(color_eyre::eyre::eyre!(
                "Invalid hash: must be hex characters"
            ))
        } else {
            Ok(Hash(value))
        }
    }
}

impl TryFrom<&str> for Hash {
    type Error = Report;

    fn try_from(value: &str) -> Result<Self> {
        if !value.as_bytes().into_iter().all(u8::is_ascii_hexdigit) {
            Err(color_eyre::eyre::eyre!(
                "Invalid hash: must be hex characters"
            ))
        } else {
            Ok(Hash(value.to_owned()))
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, From, Into)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Address(pub String);

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Token(#[serde(with = "token_serde")] [u8; 2]);

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap()
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Token").field(&self.as_ref()).finish()
    }
}

impl TryFrom<&str> for Token {
    type Error = Report;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 2 {
            let arr = <[u8; 2]>::try_from(value.as_bytes())?;
            Ok(Token(arr))
        } else {
            Err(color_eyre::eyre::eyre!(
                "expected str of length 2: {}",
                value
            ))
        }
    }
}

mod token_serde {
    use serde::{de::Visitor, Deserializer, Serializer};

    pub(super) fn serialize<S>(token: &[u8; 2], ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let token_as_str = std::str::from_utf8(token).unwrap();
        ser.serialize_str(token_as_str)
    }

    struct TokVisitor;
    impl<'de> Visitor<'de> for TokVisitor {
        type Value = [u8; 2];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string of length 2")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.len() == 2 {
                let arr = <[u8; 2]>::try_from(v.as_bytes()).unwrap();
                Ok(arr)
            } else {
                Err(E::custom(format!("str len not 2: {}", v)))
            }
        }
    }

    pub(super) fn deserialize<'de, D>(de: D) -> Result<[u8; 2], D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_str(TokVisitor)
    }
}

pub struct MerkNode;

impl<'a> BytesEncode<'a> for MerkNode {
    type EItem = Node;

    fn bytes_encode(
        item: &'a Self::EItem,
    ) -> Result<std::borrow::Cow<'a, [u8]>, Box<dyn StdError>> {
        let bytes = serde_bytes::ByteBuf::from(serde_cbor::to_vec(item)?);
        Ok(serde_cbor::to_vec(&bytes).map(Cow::Owned)?)
    }
}

impl<'a> BytesDecode<'a> for MerkNode {
    type DItem = Node;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, Box<dyn StdError>> {
        let bytes: serde_cbor::value::Value = serde_cbor::from_slice(bytes)?;
        if let serde_cbor::value::Value::Bytes(bytes) = bytes {
            // println!("bytes = {:?}", bytes);
            Ok(serde_cbor::from_slice(&bytes)?)
        } else {
            Err(color_eyre::eyre::eyre!("invalid type: expected bytes"))?
        }
    }
}

pub struct HashEnc;

impl<'a> BytesEncode<'a> for HashEnc {
    type EItem = Hash;

    fn bytes_encode(item: &'a Self::EItem) -> Result<Cow<'a, [u8]>, Box<dyn StdError>> {
        Ok(item.0.as_bytes().into())
    }
}

impl<'a> BytesDecode<'a> for HashEnc {
    type DItem = Hash;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, Box<dyn StdError>> {
        Ok(String::from_utf8(bytes.into())?.try_into()?)
    }
}

pub type StateDatabase = heed::Database<HashEnc, heed::types::ByteSlice>;

pub struct MerkleTree<'db> {
    env: heed::Env,
    db: &'db StateDatabase,
    root_hash: Hash,
}

impl<'db> MerkleTree<'db> {
    pub fn new(env: heed::Env, db: &'db StateDatabase, root_hash: Hash) -> Result<Self> {
        Ok(Self { env, db, root_hash })
    }

    #[allow(dead_code)]
    pub fn get(&self, hash: &Hash) -> Result<Option<Node>> {
        let rtxn = self.env.read_txn().wrap_err()?;
        let node = self
            .db
            .get(&rtxn, hash)
            .wrap_err()?
            .map(Node::from_bytes)
            .transpose()?;
        rtxn.commit().wrap_err()?;
        Ok(node)
    }

    pub fn get_bytes<'a>(&self, hash: &Hash, rtxn: &'a RoTxn) -> Result<Option<&'a [u8]>> {
        let bytes = self.db.get(&rtxn, hash).wrap_err()?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    /// Visits each node in the merkle tree through a breadth-first traversal,
    /// running the `visitor` upon visiting each node
    pub fn visit(&self, mut visitor: impl FnMut(&Node)) -> Result<()> {
        let mut queue = VecDeque::new();
        queue.push_back(self.root_hash.clone());

        while let Some(current_hash) = queue.pop_front() {
            match self.get(&current_hash) {
                Ok(Some(current)) => {
                    // log::trace!("{} children", current.children.len());
                    visitor(&current);

                    for (_token, hash) in &current.children {
                        queue.push_back(hash.clone());
                    }
                }
                Ok(None) => log::error!("node with hash {:?} not found", current_hash),
                Err(e) => log::error!(
                    "error occurred while fetch node at {:?}: {}",
                    current_hash,
                    e
                ),
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    /// Visits each node in the merkle tree in parallel. This is guaranteed to visit all nodes,
    /// but the order in which nodes are visited is non-deterministic.
    pub fn par_visit(&self, visitor: impl Fn(&Node) + Send + Sync) -> Result<()> {
        let queue = Mutex::new(VecDeque::from([self.root_hash.clone()]));
        let running = AtomicU64::new(0);
        let mut first = true;

        rayon::scope(|s| {
            while running.load(std::sync::atomic::Ordering::SeqCst) > 0 || first {
                first = false;
                while let Some(hash) = queue.lock().unwrap().pop_front() {
                    running.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    s.spawn(|_| {
                        let hash = hash;
                        match self.get(&hash) {
                            Ok(Some(current)) => {
                                // log::trace!("{} children", current.children.len());
                                visitor(&current);

                                for (_token, hash) in &current.children {
                                    queue.lock().unwrap().push_back(hash.clone());
                                }
                            }
                            Ok(None) => log::error!("node with hash {:?} not found", hash),
                            Err(e) => {
                                log::error!("error occurred while fetch node at {:?}: {}", hash, e)
                            }
                        }
                        running.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    });
                }
            }
        });

        Ok(())
    }

    pub fn copy_to_db(&self, new_env: heed::Env, new_db: &StateDatabase) -> Result<()> {
        let queue = parking_lot::Mutex::new(VecDeque::from([self.root_hash.clone()]));
        let running = AtomicU64::new(0);
        let mut first = true;
        let new_env = parking_lot::Mutex::new(new_env);

        let written = AtomicU64::new(0);

        rayon::scope(|s| {
            while running.load(std::sync::atomic::Ordering::SeqCst) > 0 || first {
                first = false;
                while let Some(hash) = queue.lock().pop_front() {
                    running.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    s.spawn(|_| {
                        let hash = hash;
                        let rtxn = self.env.read_txn().wrap_err().unwrap();
                        match self.get_bytes(&hash, &rtxn) {
                            Ok(Some(current)) => {
                                {
                                    let new_env = new_env.lock();
                                    let mut wtxn = new_env.write_txn().wrap_err().unwrap();
                                    new_db.put(&mut wtxn, &hash, &current).wrap_err().unwrap();
                                    wtxn.commit().wrap_err().unwrap();
                                }
                                let count =
                                    written.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if count % 1000 == 0 {
                                    log::trace!("{} entries written", count,);
                                }

                                let current = Node::from_bytes(current).unwrap();
                                rtxn.commit().wrap_err().unwrap();
                                for hash in current.children.into_values() {
                                    let mut queue = queue.lock();
                                    queue.push_back(hash);
                                }
                            }
                            Ok(None) => log::error!("node with hash {:?} not found", hash),
                            Err(e) => {
                                log::error!(
                                    "error occurred while fetching node at {:?}: {}",
                                    hash,
                                    e
                                )
                            }
                        }
                        running.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    });
                }
            }
        });

        Ok(())
    }
    // pub fn copy_to_db(&self, new_env: heed::Env, new_db: &StateDatabase) -> Result<()> {
    //     let mut queue = VecDeque::new();
    //     queue.push_back(self.root_hash.clone());

    //     while let Some(current_hash) = queue.pop_front() {
    //         match self.get(&current_hash) {
    //             Ok(Some(current)) => {
    //                 // log::trace!("{} children", current.children.len());
    //                 {
    //                     let mut wtxn = new_env.write_txn().wrap_err().unwrap();
    //                     new_db.put(&mut wtxn, &current_hash, &current).wrap_err().unwrap();
    //                     wtxn.commit().wrap_err().unwrap();
    //                 }

    //                 for (_token, hash) in &current.children {
    //                     queue.push_back(hash.clone());
    //                 }
    //             }
    //             Ok(None) => log::error!("node with hash {:?} not found", current_hash),
    //             Err(e) => log::error!(
    //                 "error occurred while fetch node at {:?}: {}",
    //                 current_hash,
    //                 e
    //             ),
    //         }
    //         // let current = ?
    //         // .ok_or_else(|| eyre!("node at {:?} not found", current_hash))?;
    //     }
    //     Ok(())
    // }
}
