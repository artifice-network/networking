use crate::asyncronous::encryption::{sym_aes_decrypt, sym_aes_encrypt};
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
use walkdir::WalkDir;

/// this is marker trait for any value of HashDatabase
pub trait HashValue: 'static + Debug + Serialize + DeserializeOwned + Clone + Send + Sync {}
/// this is a marker trait for any key value of HashDatabase
pub trait HashKey: 'static + Hash + AsRef<Path> + PartialEq + Eq + Clone + Send + Sync {}
impl<V> HashValue for V where V: 'static + Debug + Serialize + DeserializeOwned + Send + Clone + Sync
{}
impl<K> HashKey for K where K: 'static + AsRef<Path> + Hash + PartialEq + Eq + Clone + Send + Sync {}
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
#[derive(Clone)]
pub struct HashDatabase<V: HashValue, K: HashKey = String> {
    data: HashMap<K, V>,
    key: Vec<u8>,
    root: PathBuf,
}
impl<V: HashValue, K: HashKey> HashDatabase<V, K> {
    /// # Arguments
    ///
    /// path: path to the root of the database
    /// key: an option of bytes used to encrypt and decrypt the database
    pub fn new<P: AsRef<Path>>(path: P, key: Vec<u8>) -> Result<Self, NetworkError> {
        let root = path.as_ref().to_path_buf();
        if !root.exists() {
            std::fs::create_dir(root.clone())?;
        }
        Ok(Self {
            data: HashMap::new(),
            key,
            root,
        })
    }
    pub fn insert(&mut self, key: K, item: V) -> Result<(), NetworkError> {
        self.data.insert(key.clone(), item.clone());
        let path = self.root.join(key.as_ref());
        let mut file = File::create(path)?;
        let mut data = serde_json::to_string(&item)?.into_bytes();
        sym_aes_encrypt(&self.key, &mut data);
        Ok(file.write_all(&data)?)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }
    pub fn load(&mut self, key: &K) -> Result<(), NetworkError> {
        let path = self.root.join(key);
        if !path.exists() {
            return Err(NetworkError::IOError(std::io::Error::new(std::io::ErrorKind::NotFound, "entry not found")));
        }
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
    pub fn read_entry<EV: HashValue>(&self, key: &K) -> Result<EV, NetworkError>{
        let mut file = File::open(self.root.join(key.as_ref()))?;
        let mut invec = Vec::new();
        file.read_to_end(&mut invec)?;
        sym_aes_decrypt(&self.key, &mut invec);
        Ok(serde_json::from_str(&String::from_utf8(invec)?)?)
    }
    /// writes entry of different type from that of the database
    /// used for special exceptions, for any large quantity of this type create a different database
    pub fn write_entry<EV: HashValue>(&self, key: &K, value: &EV) -> Result<(), NetworkError>{
        let mut file = File::open(self.root.join(key.as_ref()))?;
        let mut outvec = serde_json::to_string(value)?.into_bytes();
        sym_aes_encrypt(&self.key,&mut outvec);
        Ok(file.write_all(&outvec)?)
    }
}
