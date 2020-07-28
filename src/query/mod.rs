/// asyncrounous implementation of bi-directional communication, that uses tokio::sync::mpsc
pub mod asyncronous;
/// syncrounous implementation of bi-directional communication, that uses std::sync::mpsc
pub mod syncronous;

pub trait Query {
    type Left;
    type Right;
    /// manually create using an existing sender and receiver
    fn create(sender: Self::Left, receiver: Self::Right) -> Self;
    /// split a query into its components
    fn split(self) -> (Self::Left, Self::Right);
    fn ref_split(&mut self) -> (&mut Self::Left, &mut Self::Right);
}
