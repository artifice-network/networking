use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;
#[derive(Debug)]
pub enum NetworkError {
    IOError(std::io::Error),
    RSAError(rsa::errors::Error),
    SerdeError(serde_json::error::Error),
    UTF8(FromUtf8Error),
    ConnectionDenied(String),
    UnSet(String),
}
impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            NetworkError::IOError(err) => format!("{}", err),
            NetworkError::RSAError(err) => format!("{}", err),
            NetworkError::SerdeError(err) => format!("{}", err),
            NetworkError::UnSet(e) => format!("{}", e),
            NetworkError::UTF8(e) => format!("{}", e),
            NetworkError::ConnectionDenied(e) => format!("{}", e),
        };
        write!(f, "{}", msg)
    }
}
impl Error for NetworkError {}
impl From<std::io::Error> for NetworkError {
    fn from(error: std::io::Error) -> NetworkError {
        NetworkError::IOError(error)
    }
}
impl From<rsa::errors::Error> for NetworkError {
    fn from(error: rsa::errors::Error) -> NetworkError {
        NetworkError::RSAError(error)
    }
}
impl From<serde_json::error::Error> for NetworkError {
    fn from(error: serde_json::error::Error) -> NetworkError {
        NetworkError::SerdeError(error)
    }
}
impl From<FromUtf8Error> for NetworkError {
    fn from(error: FromUtf8Error) -> NetworkError {
        NetworkError::UTF8(error)
    }
}
