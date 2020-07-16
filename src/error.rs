#[derive(Debug)]
pub enum NetworkError {
    IOError(std::io::Error),
    RSAError(rsa::errors::Error),
    SerdeError(serde_json::error::Error),
}