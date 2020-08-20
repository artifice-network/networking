use crate::encryption::{
    simple_aes_decrypt as sym_aes_decrypt, simple_aes_encrypt as sym_aes_encrypt,
};
use crate::error::NetworkError;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::hash_map::{IntoIter, Iter, IterMut};
use std::collections::HashMap;
use std::fmt;
use std::iter::IntoIterator;
use std::path::Path;
use std::path::PathBuf;

use std::fs::File;
use std::io::{Read, Write};
use std::{fmt::Debug, hash::Hash};
use tar::{Archive, Builder};
use walkdir::WalkDir;

/// this is marker trait for any value of HashDatabase
pub trait HashValue: 'static + Debug + Serialize + DeserializeOwned + Clone + Send + Sync {}
/// this is a marker trait for any key value of HashDatabase
pub trait HashKey: 'static + Hash + ToString + PartialEq + Eq + Clone + Send + Sync {}
impl<V> HashValue for V where V: 'static + Debug + Serialize + DeserializeOwned + Send + Clone + Sync
{}
impl<K> HashKey for K where K: 'static + ToString + Hash + PartialEq + Eq + Clone + Send + Sync {}
impl<V: HashValue, K: HashKey> Debug for HashDatabase<V, K>
where
    K: Debug,
    V: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Point")
            .field("data", &self.data)
            .field("key", &self.key)
            .field("root", &self.root)
            .finish()
    }
}
/// these trait implementations are taken directly from std::collections::HashMap
/// note that currently these implementations will only return data already loaded into memory
impl<'a, V: HashValue, K: HashKey> IntoIterator for &'a HashDatabase<V, K> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Iter<'a, K, V> {
        self.data.iter()
    }
}
impl<V: HashValue, K: HashKey> IntoIterator for HashDatabase<V, K> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;
    fn into_iter(self) -> IntoIter<K, V> {
        self.data.into_iter()
    }
}
impl<'a, V: HashValue, K: HashKey> IntoIterator for &'a mut HashDatabase<V, K> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    #[inline]
    fn into_iter(self) -> IterMut<'a, K, V> {
        self.data.iter_mut()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct EmptyMeta {}
#[derive(Clone)]
pub struct HashDatabase<V: HashValue, K: HashKey = String, M: HashValue = EmptyMeta> {
    data: HashMap<K, V>,
    meta: Option<M>,
    key: Vec<u8>,
    root: PathBuf,
}
impl<V: HashValue, K: HashKey, M: HashValue> HashDatabase<V, K, M> {
    /// # Arguments
    ///
    /// path: path to the root of the database
    /// key: an option of bytes used to encrypt and decrypt the database
    pub fn new<P: AsRef<Path>>(path: P, key: Vec<u8>) -> Result<Self, NetworkError> {
        let meta_path = path.as_ref().to_path_buf();
        if meta_path.exists() {
            let mut file = File::open(meta_path)?;
            let mut invec = Vec::new();
            file.read_to_end(&mut invec)?;
            sym_aes_decrypt(&key, &mut invec);
            let entry = serde_json::from_str(&String::from_utf8(invec)?)?;
            return Self::from_hashmap(HashMap::new(), Some(entry), path, key);
        }
        Self::from_hashmap(HashMap::new(), None, path, key)
    }
    pub fn from_hashmap<P: AsRef<Path>>(data: HashMap<K, V>, meta: Option<M>, path: P, key: Vec<u8>) -> Result<Self, NetworkError> {
        let root = path.as_ref().to_path_buf();
        if !root.exists() {
            std::fs::create_dir(root.clone())?;
        }
        Ok(Self {
            data,
            meta,
            key,
            root,
        })
    }
    pub fn insert(&mut self, key: K, item: V) -> Result<(), NetworkError> {
        self.data.insert(key.clone(), item.clone());
        let path_str = key.to_string();
        let path = self.root.join(path_str);
        let mut file = File::create(path)?;
        let mut data = serde_json::to_string(&item)?.into_bytes();
        sym_aes_encrypt(&self.key, &mut data);
        Ok(file.write_all(&data)?)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }
    pub fn load_meta(&mut self) -> Result<(), NetworkError>{
        let path = self.root.join("meta.artusr");
        let mut file = File::open(path)?;
        let mut invec = Vec::new();
        file.read_to_end(&mut invec)?;
        sym_aes_decrypt(&self.key, &mut invec);
        let entry = serde_json::from_str(&String::from_utf8(invec)?)?;
        self.meta = Some(entry);
        Ok(())
    }
    pub fn load(&mut self, key: &K) -> Result<(), NetworkError> {
        if self.data.get(key).is_some() {
            return Ok(());
        }
        let path_str = key.to_string();
        let path = self.root.join(path_str);
        let mut file = File::open(path)?;
        let mut invec = Vec::new();
        file.read_to_end(&mut invec)?;
        sym_aes_decrypt(&self.key, &mut invec);
        let entry = serde_json::from_str(&String::from_utf8(invec)?)?;
        self.data.insert(key.clone(), entry);
        Ok(())
    }
    pub fn decompose(self) -> (HashMap<K, V>, PathBuf) {
        (self.data, self.root)
    }
    /// indexes all files in the root
    /// note that this function is highly inefficient, as such it should only be called when absolutely needed
    pub fn index_entries(&self) -> Result<Vec<PathBuf>, NetworkError> {
        let results: Vec<Result<PathBuf, NetworkError>> = WalkDir::new(self.root.clone())
            .into_iter()
            .map(|p| Ok(p?.path().to_path_buf()))
            .collect();
        let mut paths = Vec::with_capacity(results.len());
        for result in results.into_iter() {
            let path = result?;
            if path.is_file() {
                paths.push(path);
            }
        }
        Ok(paths)
    }
    /// indexes all directories in the root
    pub fn index_subdatabases(&self) -> Result<Vec<PathBuf>, NetworkError> {
        let results: Vec<Result<PathBuf, NetworkError>> = WalkDir::new(self.root.clone())
            .into_iter()
            .map(|p| Ok(p?.path().to_path_buf()))
            .collect();
        let mut paths = Vec::with_capacity(results.len());
        for result in results.into_iter() {
            let path = result?;
            if path.is_dir() {
                paths.push(path);
            }
        }
        Ok(paths)
    }
    /// reads entry of a different type from the database
    /// used for special exceptions, for any large quantity of this type create a different database
    pub fn read_entry<EV: HashValue>(&self, key: &K) -> Result<EV, NetworkError> {
        let path_str = key.to_string();
        let path = self.root.join(path_str);
        let mut file = File::open(path)?;
        let mut invec = Vec::new();
        file.read_to_end(&mut invec)?;
        sym_aes_decrypt(&self.key, &mut invec);
        Ok(serde_json::from_str(&String::from_utf8(invec)?)?)
    }
    /// writes entry of different type from that of the database
    /// used for special exceptions, for any large quantity of this type create a different database
    pub fn write_entry<EV: HashValue>(&self, key: &K, value: &EV) -> Result<(), NetworkError> {
        let path_str = key.to_string();
        let path = self.root.join(path_str);
        let mut file = File::open(path)?;
        let mut outvec = serde_json::to_string(value)?.into_bytes();
        sym_aes_encrypt(&self.key, &mut outvec);
        Ok(file.write_all(&outvec)?)
    }
    /// converts the database to an in memory tar file
    pub fn archive(&self) -> Result<Vec<u8>, NetworkError> {
        let archive = Vec::new();
        let mut builder = Builder::new(archive);
        let results: Vec<std::io::Result<()>> = WalkDir::new(self.root.clone())
            .into_iter()
            .map(|p| p.unwrap().into_path())
            .filter(|p| p.is_file())
            .map(|p| builder.append_path(p))
            .collect();
        for result in results.into_iter() {
            result?
        }
        Ok(builder.into_inner()?)
    }
    /// takes an in memory tar file and writes it to the disk
    pub fn dearchive(&self, archive_data: &[u8]) -> std::io::Result<()> {
        let mut archive = Archive::new(archive_data);
        for entry in archive.entries()? {
            let mut entry = entry?;
            entry.unpack(self.root.join(entry.path()?))?;
        }
        Ok(())
    }
    pub fn meta(&self) -> &Option<M> {
        &self.meta
    }
}
