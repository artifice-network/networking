use crate::error::NetworkError;
use crate::query::Query;
use std::sync::mpsc::{channel, Receiver, Sender};
pub fn sync_channel<R, S>() -> (SyncQuery<R, S>, SyncQuery<S, R>) {
    let (l_sender, l_receiver) = channel();
    let (r_sender, r_receiver) = channel();
    (
        SyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        SyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct SyncQuery<S, R> {
    sender: Sender<S>,
    receiver: Receiver<R>,
}
impl<S, R> SyncQuery<S, R> {
    pub fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data)?)
    }
    pub fn recv(&mut self) -> Result<R, NetworkError> {
        Ok(self.receiver.recv()?)
    }
}
impl<S, R> Query for SyncQuery<S, R> {
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
