use core::fmt;
use std::sync::{Arc, Mutex};

use send_wrapper::SendWrapper;

#[derive(Debug, Clone)]
pub struct HeedError(Arc<Mutex<SendWrapper<heed::Error>>>);

impl fmt::Display for HeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.lock().unwrap().fmt(f)
    }
}

impl std::error::Error for HeedError {}

impl HeedError {
    pub fn new(error: heed::Error) -> Self {
        Self(Arc::new(Mutex::new(SendWrapper::new(error))))
    }
}
