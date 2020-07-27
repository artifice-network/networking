use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError as SyncRecvError;
use std::sync::mpsc::SendError as SyncSendError;
use tokio::sync::mpsc::error::RecvError as AsyncRecvError;
use tokio::sync::mpsc::error::SendError as AsyncSendError;
#[derive(Debug)]
pub enum NetworkError {
    IOError(std::io::Error),
    RSAError(rsa::errors::Error),
    SerdeError(serde_json::error::Error),
    UTF8(FromUtf8Error),
    ConnectionDenied(String),
    FromSlice(TryFromSliceError),
    UnSet(String),
    AsyncSendError(String),
    AsyncRecvError(String),
    SyncSendError(String),
    SyncRecvError(String),
}
impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            NetworkError::IOError(err) => format!("{}", err),
            NetworkError::RSAError(err) => format!("{}", err),
            NetworkError::SerdeError(err) => format!("{}", err),
            NetworkError::UnSet(e) => e.to_string(),
            NetworkError::UTF8(e) => format!("{}", e),
            NetworkError::ConnectionDenied(e) => e.to_string(),
            NetworkError::FromSlice(e) => format!("{}", e),
            NetworkError::AsyncSendError(e) => e.to_string(),
            NetworkError::AsyncRecvError(e) => e.to_string(),
            NetworkError::SyncSendError(e) => e.to_string(),
            NetworkError::SyncRecvError(e) => e.to_string(),
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
impl From<TryFromSliceError> for NetworkError {
    fn from(error: TryFromSliceError) -> Self {
        NetworkError::FromSlice(error)
    }
}
impl<T> From<AsyncSendError<T>> for NetworkError {
    fn from(error: AsyncSendError<T>) -> NetworkError {
        NetworkError::AsyncSendError(format!("{}", error))
    }
}
impl From<AsyncRecvError> for NetworkError {
    fn from(error: AsyncRecvError) -> NetworkError {
        NetworkError::AsyncRecvError(format!("{}", error))
    }
}
impl<T> From<SyncSendError<T>> for NetworkError {
    fn from(error: SyncSendError<T>) -> NetworkError {
        NetworkError::SyncSendError(format!("{}", error))
    }
}
impl From<SyncRecvError> for NetworkError {
    fn from(error: SyncRecvError) -> NetworkError {
        NetworkError::SyncRecvError(format!("{}", error))
    }
}
