use crate::error::NetworkError;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::hash_map::{IntoIter, Iter, IterMut};
use std::collections::HashMap;
use std::fmt;
use std::iter::IntoIterator;
use std::path::Path;
use std::path::PathBuf;
use std::{fmt::Debug, hash::Hash};
use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncReadExt};
use tokio::task::JoinHandle;
use tokio::sync::RwLock;
use std::sync::Arc;
use walkdir::WalkDir;
use crate::asyncronous::encryption::sym_aes_decrypt;

pub trait HashValue: 'static + Serialize + DeserializeOwned + Clone + Send + Sync {}
pub trait HashKey:
    'static + Hash + AsRef<Path> + PartialEq + Eq + Clone + DeserializeOwned + Serialize + Send + Sync
{
}
impl<V> HashValue for V where V: 'static + Serialize + DeserializeOwned + Send + Clone + Sync {}
impl<K> HashKey for K where
    K: 'static
        + AsRef<Path>
        + Hash
        + PartialEq
        + Eq
        + Clone
        + DeserializeOwned
        + Serialize
        + Send
        + Sync
{
}
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
    temp_map: Arc<RwLock<Vec<(K, V)>>>,
    data: HashMap<K, V>,
    key: Vec<u8>,
    root: PathBuf,
}
impl<V: HashValue, K: HashKey> HashDatabase<V, K> {
    /// # Arguments
    ///
    /// path: path to the root of the database
    /// key: an option of bytes used to encrypt and decrypt the database
    pub fn new<P: AsRef<Path>>(path: P, key: Vec<u8>) -> Self {
        let root = path.as_ref().to_path_buf();
        Self {
            data: HashMap::new(),
            key,
            root,
            temp_map: Arc::new(RwLock::new(Vec::new())),
        }
    }
    pub fn insert(&mut self, key: K, item: V) {
        self.data.insert(key, item);
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }
    pub fn decompose(self) -> (HashMap<K, V>, PathBuf) {
        (self.data, self.root)
    }
    /// # Arguments
    ///
    /// path: path to the root of the database
    /// key: an option of bytes used to encrypt and decrypt the database
    pub fn from_hashmap<P: AsRef<Path>>(
        data: HashMap<K, V>,
        path: P,
        key: Vec<u8>,
    ) -> Self {
        let root = path.as_ref().to_path_buf();
        Self {
            data,
            root,
            key,
            temp_map: Arc::new(RwLock::new(Vec::new())),
        }
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
    pub async fn load(&self, entries: Vec<K>) -> JoinHandle<Result<usize, NetworkError>>{
        let root = self.root.clone();
        let temp_map = self.temp_map.clone();
        let key = self.key.clone();
        tokio::spawn(async move {
            let len = entries.len();
            for entry in entries.into_iter() {
                let path = root.join(entry.as_ref());
                let mut file = AsyncFile::open(path).await?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).await?;
                sym_aes_decrypt(&key, &mut buffer);
                let value = toml::from_str(&String::from_utf8(buffer)?)?;
                temp_map.write().await.push((entry, value));
            }
            Ok(len)
        })
    }
    pub async fn memory_sync(&mut self){
        for (k,v) in self.temp_map.read().await.iter() {
            self.data.insert(k.clone(),v.clone());
        }
        self.temp_map.write().await.clear();
    }
}
