/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::io::Cursor;
use std::{cmp::Reverse, collections::BTreeMap};

// use

use cbor::decoder::GenericDecoder;
use cbor::encoder::GenericEncoder;
use cbor::value::Bytes;
use cbor::value::Key;
use cbor::value::Text;
use cbor::value::Value;

use crate::hash::sha512_digest_bytes;

use protobuf::Message;

use crate::database::error::DatabaseError;
use crate::database::lmdb::DatabaseReader;
use crate::database::lmdb::LmdbDatabase;
use crate::database::lmdb::LmdbDatabaseWriter;

use crate::proto::merkle::ChangeLogEntry;
use crate::proto::merkle::ChangeLogEntry_Successor;

use crate::state::error::StateDatabaseError;
use crate::state::{StateIter, StateReader};

const TOKEN_SIZE: usize = 2;

pub const CHANGE_LOG_INDEX: &str = "change_log";
pub const DUPLICATE_LOG_INDEX: &str = "duplicate_log";
pub const INDEXES: [&str; 2] = [CHANGE_LOG_INDEX, DUPLICATE_LOG_INDEX];

type StateHash = Vec<u8>;

/// Merkle Database
#[derive(Clone)]
pub struct MerkleDatabase {
    root_hash: String,
    db: LmdbDatabase,
    root_node: Node,
}

impl MerkleDatabase {
    /// Constructs a new MerkleDatabase, backed by a given Database
    ///
    /// An optional starting merkle root may be provided.
    pub fn new(db: LmdbDatabase, merkle_root: Option<&str>) -> Result<Self, StateDatabaseError> {
        let root_hash = merkle_root.unwrap().to_owned();
        // let root_hash = merkle_root.map_or_else(|| initialize_db(&db), |s| Ok(s.into()))?;
        let root_node = get_node_by_hash(&db, &root_hash)?;

        Ok(MerkleDatabase {
            root_hash,
            db,
            root_node,
        })
    }

    /// Prunes nodes that are no longer needed under a given state root
    /// Returns a list of addresses that were deleted
    pub fn prune(db: &LmdbDatabase, merkle_root: &str) -> Result<Vec<String>, StateDatabaseError> {
        let root_bytes = ::hex::decode(merkle_root).map_err(|_| {
            StateDatabaseError::InvalidHash(format!("{} is not a valid hash", merkle_root))
        })?;
        let mut db_writer = db.writer()?;
        let change_log = get_change_log(&db_writer, &root_bytes)?;

        if change_log.is_none() {
            // There's no change log for this entry
            return Ok(vec![]);
        }

        let mut change_log = change_log.unwrap();
        let removed_addresses = if change_log.get_successors().len() > 1 {
            // Currently, we don't clean up a parent with multiple successors
            vec![]
        } else if change_log.get_successors().is_empty() {
            // deleting the tip of a trie lineage

            let (deletion_candidates, duplicates) = MerkleDatabase::remove_duplicate_hashes(
                &mut db_writer,
                change_log.take_additions(),
            )?;

            for hash in &deletion_candidates {
                let hash_hex = ::hex::encode(hash);
                delete_ignore_missing(&mut db_writer, hash_hex.as_bytes())?
            }

            for hash in &duplicates {
                decrement_ref_count(&mut db_writer, hash)?;
            }

            db_writer.index_delete(CHANGE_LOG_INDEX, &root_bytes)?;
            let parent_root_bytes = &change_log.get_parent();

            if let Some(ref mut parent_change_log) =
                get_change_log(&db_writer, parent_root_bytes)?.as_mut()
            {
                let successors = parent_change_log.take_successors();
                let new_successors = successors
                    .into_iter()
                    .filter(|successor| root_bytes != successor.get_successor())
                    .collect::<Vec<_>>();
                parent_change_log.set_successors(protobuf::RepeatedField::from_vec(new_successors));

                write_change_log(&mut db_writer, parent_root_bytes, &parent_change_log)?;
            }

            deletion_candidates.into_iter().collect()
        } else {
            // deleting a parent
            let mut successor = change_log.take_successors().pop().unwrap();

            let mut deletions = successor.take_deletions();
            deletions.push(root_bytes.clone());

            let (deletion_candidates, duplicates): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
                MerkleDatabase::remove_duplicate_hashes(&mut db_writer, deletions)?;

            for hash in &deletion_candidates {
                let hash_hex = ::hex::encode(hash);
                delete_ignore_missing(&mut db_writer, hash_hex.as_bytes())?
            }

            for hash in &duplicates {
                decrement_ref_count(&mut db_writer, hash)?;
            }

            db_writer.index_delete(CHANGE_LOG_INDEX, &root_bytes)?;

            deletion_candidates.into_iter().collect()
        };

        db_writer.commit()?;
        Ok(removed_addresses.iter().map(::hex::encode).collect())
    }

    pub(crate) fn remove_duplicate_hashes(
        db_writer: &mut LmdbDatabaseWriter,
        deletions: protobuf::RepeatedField<Vec<u8>>,
    ) -> Result<(Vec<StateHash>, Vec<StateHash>), StateDatabaseError> {
        Ok(deletions.into_iter().partition(|key| {
            if let Ok(count) = get_ref_count(db_writer, &key) {
                count == 0
            } else {
                false
            }
        }))
    }

    /// Returns the current merkle root for this MerkleDatabase
    pub fn get_merkle_root(&self) -> String {
        self.root_hash.clone()
    }

    /// Sets the current merkle root for this MerkleDatabase
    pub fn set_merkle_root<S: Into<String>>(
        &mut self,
        merkle_root: S,
    ) -> Result<(), StateDatabaseError> {
        let new_root = merkle_root.into();
        self.root_node = get_node_by_hash(&self.db, &new_root)?;
        self.root_hash = new_root;
        Ok(())
    }

    /// Sets the given data at the given address.
    ///
    /// Returns a Result with the new merkle root hash, or an error if the
    /// address is not in the tree.
    ///
    /// Note, continued calls to get, without changing the merkle root to the
    /// result of this function, will not retrieve the results provided here.
    pub fn set(&self, address: &str, data: &[u8]) -> Result<String, StateDatabaseError> {
        let mut updates = HashMap::with_capacity(1);
        updates.insert(address.to_string(), data.to_vec());
        self.update(&updates, &[], false)
    }

    /// Deletes the value at the given address.
    ///
    /// Returns a Result with the new merkle root hash, or an error if the
    /// address is not in the tree.
    ///
    /// Note, continued calls to get, without changing the merkle root to the
    /// result of this function, will still retrieve the data at the address
    /// provided
    pub fn delete(&self, address: &str) -> Result<String, StateDatabaseError> {
        self.update(&HashMap::with_capacity(0), &[address.to_string()], false)
    }

    /// Updates the tree with multiple changes.  Applies both set and deletes,
    /// as given.
    ///
    /// If the flag `is_virtual` is set, the values are not written to the
    /// underlying database.
    ///
    /// Returns a Result with the new root hash.
    pub fn update(
        &self,
        set_items: &HashMap<String, Vec<u8>>,
        delete_items: &[String],
        is_virtual: bool,
    ) -> Result<String, StateDatabaseError> {
        let mut path_map = HashMap::new();

        let mut deletions = HashSet::new();
        let mut additions = HashSet::new();

        for (set_address, set_value) in set_items {
            let tokens = tokenize_address(set_address);
            let mut set_path_map = self.get_path_by_tokens(&tokens, false)?;

            {
                let node = set_path_map
                    .get_mut(set_address)
                    .expect("Path map not correctly generated");
                node.value = Some(set_value.to_vec());
            }
            path_map.extend(set_path_map);
        }
        for pkey in path_map.keys() {
            additions.insert(pkey.clone());
        }

        for del_address in delete_items.iter() {
            let tokens = tokenize_address(del_address);
            let del_path_map = self.get_path_by_tokens(&tokens, true)?;
            path_map.extend(del_path_map);
        }

        for del_address in delete_items.iter() {
            path_map.remove(del_address);
            let (mut parent_address, mut path_branch) = parent_and_branch(del_address);
            while !parent_address.is_empty() {
                let remove_parent = {
                    let parent_node = path_map
                        .get_mut(parent_address)
                        .expect("Path map not correctly generated or entry is deleted");

                    if let Some(old_hash_key) = parent_node.children.remove(path_branch) {
                        deletions.insert(old_hash_key);
                    }

                    parent_node.children.is_empty()
                };

                // there's no children to the parent node already in the tree, remove it from
                // path_map if a new node doesn't have this as its parent
                if remove_parent && !additions.contains(parent_address) {
                    // empty node delete it.
                    path_map.remove(parent_address);
                } else {
                    // found a node that is not empty no need to continue
                    break;
                }

                let (next_parent, next_branch) = parent_and_branch(parent_address);
                parent_address = next_parent;
                path_branch = next_branch;

                if parent_address.is_empty() {
                    let parent_node = path_map
                        .get_mut(parent_address)
                        .expect("Path map not correctly generated or entry is deleted");

                    if let Some(old_hash_key) = parent_node.children.remove(path_branch) {
                        deletions.insert(old_hash_key);
                    }
                }
            }
        }

        let mut sorted_paths: Vec<_> = path_map.keys().cloned().collect();
        // Sort by longest to shortest
        sorted_paths.sort_by_key(|a| Reverse(a.len()));

        // initializing this to empty, to make the compiler happy
        let mut key_hash = Vec::with_capacity(0);
        let mut batch = Vec::with_capacity(sorted_paths.len());
        for path in sorted_paths {
            let node = path_map
                .remove(&path)
                .expect("Path map keys are out of sink");
            let (hash_key, packed) = encode_and_hash(node)?;
            key_hash = hash_key.clone();

            if !path.is_empty() {
                let (parent_address, path_branch) = parent_and_branch(&path);
                let parent = path_map
                    .get_mut(parent_address)
                    .expect("Path map not correctly generated or entry is deleted");
                if let Some(old_hash_key) = parent
                    .children
                    .insert(path_branch.to_string(), ::hex::encode(hash_key.clone()))
                {
                    deletions.insert(old_hash_key);
                }
            }

            batch.push((hash_key, packed));
        }

        if !is_virtual {
            let deletions: Vec<Vec<u8>> = deletions
                .iter()
                // We expect this to be hex, since we generated it
                .map(|s| ::hex::decode(s).expect("Improper hex"))
                .collect();
            self.store_changes(&key_hash, &batch, &deletions)?;
        }

        Ok(::hex::encode(key_hash))
    }

    /// Puts all the items into the database.
    fn store_changes(
        &self,
        successor_root_hash: &[u8],
        batch: &[(Vec<u8>, Vec<u8>)],
        deletions: &[Vec<u8>],
    ) -> Result<(), StateDatabaseError> {
        let mut db_writer = self.db.writer()?;

        // We expect this to be hex, since we generated it
        let root_hash_bytes = ::hex::decode(&self.root_hash).expect("Improper hex");

        for &(ref key, ref value) in batch {
            match db_writer.put(::hex::encode(key).as_bytes(), &value) {
                Ok(_) => continue,
                Err(DatabaseError::DuplicateEntry) => {
                    increment_ref_count(&mut db_writer, key)?;
                }
                Err(err) => return Err(StateDatabaseError::from(err)),
            }
        }

        let mut current_change_log = get_change_log(&db_writer, &root_hash_bytes)?;
        if let Some(change_log) = current_change_log.as_mut() {
            let successors = change_log.mut_successors();
            let mut successor = ChangeLogEntry_Successor::new();
            successor.set_successor(Vec::from(successor_root_hash));
            successor.set_deletions(protobuf::RepeatedField::from_slice(deletions));
            successors.push(successor);
        }

        let mut next_change_log = ChangeLogEntry::new();
        next_change_log.set_parent(root_hash_bytes.clone());
        next_change_log.set_additions(protobuf::RepeatedField::from(
            batch
                .iter()
                .map(|&(ref hash, _)| hash.clone())
                .collect::<Vec<Vec<u8>>>(),
        ));

        if current_change_log.is_some() {
            write_change_log(
                &mut db_writer,
                &root_hash_bytes,
                &current_change_log.unwrap(),
            )?;
        }
        write_change_log(&mut db_writer, successor_root_hash, &next_change_log)?;

        db_writer.commit()?;
        Ok(())
    }

    pub(crate) fn get_by_address(&self, address: &str) -> Result<Node, StateDatabaseError> {
        let tokens = tokenize_address(address);

        // There's probably a better way to do this than a clone
        let mut node = self.root_node.clone();

        for token in tokens.iter() {
            node = match node.children.get(&token.to_string()) {
                None => {
                    return Err(StateDatabaseError::NotFound(format!(
                        "invalid address {} from root {}",
                        address, self.root_hash
                    )));
                }
                Some(child_hash) => get_node_by_hash(&self.db, child_hash)?,
            }
        }
        Ok(node)
    }

    pub(crate) fn get_path_by_tokens(
        &self,
        tokens: &[&str],
        strict: bool,
    ) -> Result<HashMap<String, Node>, StateDatabaseError> {
        let mut nodes = HashMap::new();

        let mut path = String::new();
        nodes.insert(path.clone(), self.root_node.clone());

        let mut new_branch = false;

        for token in tokens {
            let node = {
                // this is safe to unwrap, because we've just inserted the path in the previous loop
                let child_address = &nodes[&path].children.get(&token.to_string());

                match (!new_branch && child_address.is_some(), strict) {
                    (true, _) => get_node_by_hash(&self.db, child_address.unwrap())?,
                    (false, true) => {
                        return Err(StateDatabaseError::NotFound(format!(
                            "invalid address {} from root {}",
                            tokens.join(""),
                            self.root_hash
                        )));
                    }
                    (false, false) => {
                        new_branch = true;
                        Node::default()
                    }
                }
            };

            path.push_str(token);
            nodes.insert(path.clone(), node);
        }
        Ok(nodes)
    }
}

impl StateReader for MerkleDatabase {
    /// Returns true if the given address exists in the MerkleDatabase;
    /// false, otherwise.
    fn contains(&self, address: &str) -> Result<bool, StateDatabaseError> {
        match self.get_by_address(address) {
            Ok(_) => Ok(true),
            Err(StateDatabaseError::NotFound(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Returns the data for a given address, if they exist at that node.  If
    /// not, returns None.  Will return an StateDatabaseError::NotFound, if the
    /// given address is not in the tree
    fn get(&self, address: &str) -> Result<Option<Vec<u8>>, StateDatabaseError> {
        Ok(self.get_by_address(address)?.value)
    }

    fn leaves(&self, prefix: Option<&str>) -> Result<Box<StateIter>, StateDatabaseError> {
        Ok(Box::new(MerkleLeafIterator::new(self.clone(), prefix)?))
    }
}

pub fn decode_cbor_value(cbor_bytes: &[u8]) -> Result<Vec<u8>, StateDatabaseError> {
    let input = Cursor::new(cbor_bytes);
    let mut decoder = GenericDecoder::new(cbor::Config::default(), input);
    let decoded_value = decoder.value()?;

    match decoded_value {
        Value::Bytes(Bytes::Bytes(bytes)) => Ok(bytes),
        _ => Err(StateDatabaseError::InvalidRecord),
    }
}

pub struct DecodedMerkleStateReader {
    merkle_database: MerkleDatabase,
}

impl DecodedMerkleStateReader {
    pub fn new(merkle_database: MerkleDatabase) -> Self {
        Self { merkle_database }
    }
}

impl StateReader for DecodedMerkleStateReader {
    fn contains(&self, address: &str) -> Result<bool, StateDatabaseError> {
        self.merkle_database.contains(address)
    }

    fn get(&self, address: &str) -> Result<Option<Vec<u8>>, StateDatabaseError> {
        Ok(match self.merkle_database.get(address)? {
            Some(bytes) => Some(decode_cbor_value(&bytes)?),
            None => None,
        })
    }
    fn leaves(&self, prefix: Option<&str>) -> Result<Box<StateIter>, StateDatabaseError> {
        Ok(Box::new(self.merkle_database.leaves(prefix)?.map(
            |value| {
                value.and_then(|(address, bytes)| {
                    decode_cbor_value(&bytes).map(|new_bytes| (address, new_bytes))
                })
            },
        )))
    }
}

/// A MerkleLeafIterator is fixed to iterate over the state address/value pairs
/// the merkle root hash at the time of its creation.
pub struct MerkleLeafIterator {
    merkle_db: MerkleDatabase,
    visited: VecDeque<(String, Node)>,
}

impl MerkleLeafIterator {
    fn new(merkle_db: MerkleDatabase, prefix: Option<&str>) -> Result<Self, StateDatabaseError> {
        let path = prefix.unwrap_or("");

        let mut visited = VecDeque::new();
        let initial_node = merkle_db.get_by_address(path)?;
        visited.push_front((path.to_string(), initial_node));

        Ok(MerkleLeafIterator { merkle_db, visited })
    }
}

impl Iterator for MerkleLeafIterator {
    type Item = Result<(String, Vec<u8>), StateDatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.visited.is_empty() {
            return None;
        }

        loop {
            if let Some((path, node)) = self.visited.pop_front() {
                if node.value.is_some() {
                    return Some(Ok((path, node.value.unwrap())));
                }

                // Reverse the list, such that we have an in-order traversal of the
                // children, based on the natural path order.
                for (child_path, hash_key) in node.children.iter().rev() {
                    let child = match get_node_by_hash(&self.merkle_db.db, hash_key) {
                        Ok(node) => node,
                        Err(err) => return Some(Err(err)),
                    };
                    let mut child_address = path.clone();
                    child_address.push_str(child_path);
                    self.visited.push_front((child_address, child));
                }
            } else {
                return None;
            }
        }
    }
}

/// Initializes a database with an empty Trie
fn initialize_db(db: &LmdbDatabase) -> Result<String, StateDatabaseError> {
    let (hash, packed) = encode_and_hash(Node::default())?;

    let mut db_writer = db.writer()?;
    let hex_hash = ::hex::encode(hash);
    // Ignore ref counts for the default, empty tree
    db_writer.overwrite(hex_hash.as_bytes(), &packed)?;
    db_writer.commit()?;

    Ok(hex_hash)
}

/// Returns the change log entry for a given root hash.
fn get_change_log<R>(
    db_reader: &R,
    root_hash: &[u8],
) -> Result<Option<ChangeLogEntry>, StateDatabaseError>
where
    R: DatabaseReader,
{
    let log_bytes = db_reader.index_get(CHANGE_LOG_INDEX, root_hash)?;

    Ok(match log_bytes {
        Some(bytes) => Some(Message::parse_from_bytes(&bytes)?),
        None => None,
    })
}

/// Writes the given change log entry to the database
fn write_change_log(
    db_writer: &mut LmdbDatabaseWriter,
    root_hash: &[u8],
    change_log: &ChangeLogEntry,
) -> Result<(), StateDatabaseError> {
    db_writer.index_put(CHANGE_LOG_INDEX, root_hash, &change_log.write_to_bytes()?)?;
    Ok(())
}

fn increment_ref_count(
    db_writer: &mut LmdbDatabaseWriter,
    key: &[u8],
) -> Result<u64, StateDatabaseError> {
    let ref_count = get_ref_count(db_writer, key)?;

    db_writer.index_put(DUPLICATE_LOG_INDEX, key, &to_bytes(ref_count + 1))?;

    Ok(ref_count)
}

fn decrement_ref_count(
    db_writer: &mut LmdbDatabaseWriter,
    key: &[u8],
) -> Result<u64, StateDatabaseError> {
    let count = get_ref_count(db_writer, key)?;
    Ok(if count == 1 {
        db_writer.index_delete(DUPLICATE_LOG_INDEX, key)?;
        0
    } else {
        db_writer.index_put(DUPLICATE_LOG_INDEX, key, &to_bytes(count - 1))?;
        count - 1
    })
}

fn get_ref_count(
    db_writer: &mut LmdbDatabaseWriter,
    key: &[u8],
) -> Result<u64, StateDatabaseError> {
    Ok(
        if let Some(ref_count) = db_writer.index_get(DUPLICATE_LOG_INDEX, key)? {
            from_bytes(&ref_count)
        } else {
            0
        },
    )
}

fn to_bytes(num: u64) -> [u8; 8] {
    unsafe { ::std::mem::transmute(num.to_le()) }
}

fn from_bytes(bytes: &[u8]) -> u64 {
    let mut num_bytes = [0u8; 8];
    num_bytes.copy_from_slice(&bytes);
    u64::from_le(unsafe { ::std::mem::transmute(num_bytes) })
}

/// This delete ignores any MDB_NOTFOUND errors
fn delete_ignore_missing(
    db_writer: &mut LmdbDatabaseWriter,
    key: &[u8],
) -> Result<(), StateDatabaseError> {
    match db_writer.delete(key) {
        Err(DatabaseError::WriterError(ref s))
            if s == "MDB_NOTFOUND: No matching key/data pair found" =>
        {
            // This can be ignored, as the record doesn't exist
            log::debug!(
                "Attempting to delete a missing entry: {}",
                ::hex::encode(key)
            );
            Ok(())
        }
        Err(err) => Err(StateDatabaseError::DatabaseError(err)),
        Ok(_) => Ok(()),
    }
}
/// Encodes the given node, and returns the hash of the bytes.
fn encode_and_hash(node: Node) -> Result<(Vec<u8>, Vec<u8>), StateDatabaseError> {
    let packed = node.into_bytes()?;
    let hash = hash(&packed);
    Ok((hash, packed))
}

/// Given a path, split it into its parent's path and the specific branch for
/// this path, such that the following assertion is true:
///
/// ```
/// let (parent_path, branch) = parent_and_branch(some_path);
/// let mut path = String::new();
/// path.push(parent_path);
/// path.push(branch);
/// assert_eq!(some_path, &path);
/// ```
fn parent_and_branch(path: &str) -> (&str, &str) {
    let parent_address = if !path.is_empty() {
        &path[..path.len() - TOKEN_SIZE]
    } else {
        ""
    };

    let path_branch = if !path.is_empty() {
        &path[(path.len() - TOKEN_SIZE)..]
    } else {
        ""
    };

    (parent_address, path_branch)
}

/// Splits an address into tokens
fn tokenize_address(address: &str) -> Box<[&str]> {
    let mut tokens: Vec<&str> = Vec::with_capacity(address.len() / TOKEN_SIZE);
    let mut i = 0;
    while i < address.len() {
        tokens.push(&address[i..i + TOKEN_SIZE]);
        i += TOKEN_SIZE;
    }
    tokens.into_boxed_slice()
}

/// Fetch a node by its hash
fn get_node_by_hash(db: &LmdbDatabase, hash: &str) -> Result<Node, StateDatabaseError> {
    match db.reader()?.get(hash.as_bytes()) {
        Some(bytes) => Node::from_bytes(&bytes),
        None => Err(StateDatabaseError::NotFound(hash.to_string())),
    }
}

/// Internal Node structure of the Radix tree
#[derive(Default, Debug, PartialEq, Clone)]
pub struct Node {
    value: Option<Vec<u8>>,
    children: BTreeMap<String, String>,
}

impl Node {
    /// Consumes this node and serializes it to bytes
    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, StateDatabaseError> {
        let mut e = GenericEncoder::new(Cursor::new(Vec::new()));

        let mut map = BTreeMap::new();
        map.insert(
            Key::Text(Text::Text("v".to_string())),
            match self.value {
                Some(bytes) => Value::Bytes(Bytes::Bytes(bytes)),
                None => Value::Null,
            },
        );

        let children = self
            .children
            .into_iter()
            .map(|(k, v)| (Key::Text(Text::Text(k)), Value::Text(Text::Text(v))))
            .collect();

        map.insert(Key::Text(Text::Text("c".to_string())), Value::Map(children));

        e.value(&Value::Map(map))?;

        Ok(e.into_inner().into_writer().into_inner())
    }

    /// Deserializes the given bytes to a Node
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Node, StateDatabaseError> {
        let input = Cursor::new(bytes);
        let mut decoder = GenericDecoder::new(cbor::Config::default(), input);
        let decoder_value = decoder.value()?;
        // println!("{:?}", decoder_value);
        let (val, children_raw) = match decoder_value {
            Value::Map(mut root_map) => (
                root_map.remove(&Key::Text(Text::Text("v".to_string()))),
                root_map.remove(&Key::Text(Text::Text("c".to_string()))),
            ),
            _ => return Err(StateDatabaseError::InvalidRecord),
        };

        let value = match val {
            Some(Value::Bytes(Bytes::Bytes(bytes))) => Some(bytes),
            Some(Value::Null) => None,
            _ => return Err(StateDatabaseError::InvalidRecord),
        };

        let children = match children_raw {
            Some(Value::Map(child_map)) => {
                let mut result = BTreeMap::new();
                for (k, v) in child_map {
                    result.insert(key_to_string(k)?, text_to_string(v)?);
                }
                result
            }
            None => BTreeMap::new(),
            _ => return Err(StateDatabaseError::InvalidRecord),
        };

        Ok(Node { value, children })
    }
}

/// Converts a CBOR Key to its String content
fn key_to_string(key_val: Key) -> Result<String, StateDatabaseError> {
    match key_val {
        Key::Text(Text::Text(s)) => Ok(s),
        _ => Err(StateDatabaseError::InvalidRecord),
    }
}

/// Converts a CBOR Text Value to its String content
fn text_to_string(text_val: Value) -> Result<String, StateDatabaseError> {
    match text_val {
        Value::Text(Text::Text(s)) => Ok(s),
        _ => Err(StateDatabaseError::InvalidRecord),
    }
}

/// Creates a hash of the given bytes
fn hash(input: &[u8]) -> Vec<u8> {
    let bytes = sha512_digest_bytes(input);
    let (hash, _rest) = bytes.split_at(bytes.len() / 2);
    hash.to_vec()
}
