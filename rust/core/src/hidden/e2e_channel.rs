//! A finished end-to-end channel between a client and a hidden service.
//!
//! From outside it behaves like an ordinary stream. Inside there are two
//! circuits of three hops each, stitched together at the meeting point, and an
//! end-to-end cipher over them. The meeting point sees only ciphertext.

use crate::hidden::e2e_session::E2ESession;
use crate::streams::message_channel::MessageChannel;
use crate::streams::multiplexed_circuit::MultiplexedCircuit;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct E2EChannel {
    stream: Arc<dyn MessageChannel>,
    session: Mutex<E2ESession>,
    // Kept alive so the underlying circuit is not torn down early.
    _circuit: MultiplexedCircuit,
    is_client_side: bool,
}

impl E2EChannel {
    pub fn new(
        stream: Arc<dyn MessageChannel>,
        circuit: MultiplexedCircuit,
        session: E2ESession,
        is_client: bool,
    ) -> E2EChannel {
        E2EChannel {
            stream,
            session: Mutex::new(session),
            _circuit: circuit,
            is_client_side: is_client,
        }
    }

    /// Whether our side arrived first. For diagnostics.
    pub fn is_client_side(&self) -> bool {
        self.is_client_side
    }

    /// How many application bytes fit into one message.
    pub fn max_message_size() -> usize {
        crate::hidden::e2e_session::MAX_MESSAGE_SIZE
    }
}

impl MessageChannel for E2EChannel {
    fn send(&self, message: &[u8]) {
        if !self.stream.is_open() || message.len() > E2EChannel::max_message_size() {
            return;
        }
        // Sealing and sending are one step under the lock: the keystream and
        // the tag chain run in order, and two threads sealing A then B but
        // sending B then A would break the chain and kill the channel.
        let mut session = self.session.lock().unwrap();
        let sealed = session.seal(message);
        self.stream.send(&sealed);
    }

    fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
        let sealed = self.stream.receive(timeout)?;
        match self.session.lock().unwrap().open(&sealed) {
            Some(message) => Some(message),
            None => {
                // A forgery or damage: the tag chain is thrown off and nothing
                // after this would check out. The conversation cannot go on.
                self.close();
                None
            }
        }
    }

    fn is_open(&self) -> bool {
        self.stream.is_open()
    }

    fn close(&self) {
        self.stream.close();
    }
}
