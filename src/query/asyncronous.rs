use crate::error::NetworkError;
use crate::query::Query;
use tokio::sync::mpsc::{channel, Receiver, Sender};
pub fn async_channel<S, R>(len: usize) -> (AsyncQuery<R, S>, AsyncQuery<S, R>) {
    let (l_sender, l_receiver): (Sender<R>, Receiver<R>) = channel(len);
    let (r_sender, r_receiver): (Sender<S>, Receiver<S>) = channel(len);
    (
        AsyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        AsyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct AsyncQuery<S, R> {
    sender: Sender<S>,
    receiver: Receiver<R>,
}
impl<S, R> AsyncQuery<S, R> {
    pub async fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data).await?)
    }
    pub async fn recv(&mut self) -> Option<R> {
        Some(self.receiver.recv().await?)
    }
}
impl<S, R> Query for AsyncQuery<S, R> {
    type Left = Sender<S>;
    type Right = Receiver<R>;
    fn create(sender: Self::Left, receiver: Self::Right) -> Self {
        Self { sender, receiver }
    }
    fn split(self) -> (Self::Left, Self::Right) {
        (self.sender, self.receiver)
    }
    fn ref_split(&mut self) -> (&mut Self::Left, &mut Self::Right){
        (&mut self.sender, &mut self.receiver)
    }
}
