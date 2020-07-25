use std::borrow::Borrow;
use std::fmt;
use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};
#[derive(Clone)]
pub struct Request<T: Clone + Debug> {
    data: Arc<Mutex<MaybeUninit<T>>>,
    data_ready: Arc<AtomicBool>,
}
impl<Req: Clone + Debug> std::future::Future for Request<Req> {
    type Output = Req;
    fn poll(self: Pin<&mut Self>, _ctx: &mut Context) -> Poll<Self::Output> {
        let ready_state = self.data_ready.load(Ordering::Relaxed);
        if ready_state {
            let data = self.data.lock().unwrap();
            return Poll::Ready(unsafe { data.deref().get_ref().clone() });
        }
        Poll::Pending
    }
}
impl<Req: Clone + Debug> Request<Req> {
    pub fn new() -> Self {
        let data = Arc::new(Mutex::new(MaybeUninit::uninit()));
        let data_ready = Arc::new(AtomicBool::new(false));
        Self { data, data_ready }
    }
    pub fn send(&self, data: Req) {
        let mut gaurd = self.data.lock().unwrap();
        unsafe {
            *gaurd.deref_mut().get_mut() = data;
        }
    }
    pub fn recv(&mut self) -> Option<Req> {
        self.next()
    }
}
impl<Req: Clone + Debug> Default for Request<Req> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: Clone + Debug> std::iter::Iterator for Request<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let ready_state = self.data_ready.load(Ordering::Relaxed);
            if ready_state {
                let data = self.data.lock().unwrap();
                return Some(data.borrow().get_ref().clone());
            }
            None
        }
    }
}
impl<T: Clone + Debug> fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ready_state = self.data_ready.load(Ordering::Relaxed);
        let ready = ready_state;
        let data = unsafe {
            if ready {
                let data = self.data.lock().unwrap();
                Some(data.deref().get_ref().clone())
            } else {
                None
            }
        };
        f.debug_struct("Response")
            .field("ready", &ready)
            .field("data", &data)
            .finish()
    }
}
#[derive(Clone)]
pub struct Response<T: Clone + Debug> {
    data: Arc<Mutex<MaybeUninit<T>>>,
    data_ready: Arc<AtomicBool>,
}
impl<Rsp: Clone + Debug> Response<Rsp> {
    pub fn new() -> Self {
        let data = Arc::new(Mutex::new(MaybeUninit::uninit()));
        let data_ready = Arc::new(AtomicBool::new(false));
        Self { data, data_ready }
    }
    pub fn send(&self, data: Rsp) {
        let mut gaurd = self.data.lock().unwrap();
        unsafe {
            *gaurd.deref_mut().get_mut() = data;
        }
    }
    pub fn recv(&mut self) -> Option<Rsp> {
        self.next()
    }
}
impl<T: Clone + Debug> std::iter::Iterator for Response<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let ready_state = self.data_ready.load(Ordering::Relaxed);
        if ready_state {
            let data = self.data.lock().unwrap();
            return Some(unsafe { data.deref().get_ref().clone() });
        }
        None
    }
}
impl<T: Clone + Debug> fmt::Debug for Response<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ready_state = self.data_ready.load(Ordering::Relaxed);
        let ready = ready_state;
        let data = unsafe {
            if ready {
                let data = self.data.lock().unwrap();
                Some(data.deref().get_ref().clone())
            } else {
                None
            }
        };
        f.debug_struct("Response")
            .field("ready", &ready)
            .field("data", &data)
            .finish()
    }
}
impl<Rsp: Clone + Debug> Default for Response<Rsp> {
    fn default() -> Self {
        Self::new()
    }
}
impl<Rsp: Clone + Debug> std::future::Future for Response<Rsp> {
    type Output = Rsp;
    fn poll(self: Pin<&mut Self>, _ctx: &mut Context) -> Poll<Self::Output> {
        let ready_state = self.data_ready.load(Ordering::Relaxed);
        if ready_state {
            let data = self.data.lock().unwrap();
            return Poll::Ready(unsafe { data.deref().get_ref().clone() });
        }
        Poll::Pending
    }
}
#[derive(Clone, Debug)]
pub struct Query<Req: Clone + Debug, Rsp: Clone + Debug> {
    request: Request<Req>,
    response: Response<Rsp>,
}
impl<Req: Clone + Debug, Rsp: Clone + Debug> Query<Req, Rsp> {
    pub fn new() -> Self {
        let request = Request::new();
        let response = Response::new();
        Self { request, response }
    }
    pub fn send_request(&self, data: Req) {
        self.request.send(data);
    }
    pub fn send_response(&self, data: Rsp) {
        self.response.send(data);
    }
    pub fn recv_request(&mut self) -> Option<Req> {
        self.request.recv()
    }
    pub fn recv_response(&mut self) -> Option<Rsp> {
        self.response.recv()
    }
}
impl<Req: Clone + Debug, Rsp: Clone + Debug> Default for Query<Req, Rsp> {
    fn default() -> Self {
        Self::new()
    }
}
impl<Req: Clone + Debug, Rsp: Clone + Debug> std::iter::Iterator for Query<Req, Rsp> {
    type Item = Req;
    fn next(&mut self) -> Option<Self::Item> {
        self.request.next()
    }
}
