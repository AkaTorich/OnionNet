//! A hidden service's introduction point.
//!
//! The service holds a long circuit to it and waits for invitations. A client
//! comes over another circuit and hands over an invitation; the introduction
//! point moves it from one circuit into the other. It knows the service's
//! public key (its address) and that somebody is interested — never where the
//! service or client is, nor what the sealed invitation says.

use crate::hidden::hidden_protocol::{self as hp, HiddenStatus, IntroOp};
use crate::identity::onion_address::{compute_fingerprint, FINGERPRINT_SIZE};
use crate::streams::port_stack::{PortService, PortStack, ServerStream};
use crate::streams::stream_payloads::well_known_ports;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// One introduction point serves no more services than this.
pub const MAX_SERVICES: usize = 64;

pub struct IntroPointService {
    /// This relay's fingerprint: a service's Establish must be signed for it.
    own_fingerprint: Vec<u8>,
    services: Mutex<HashMap<Vec<u8>, Arc<ServerStream>>>,
    forwarded: AtomicUsize,
}

impl IntroPointService {
    pub fn new(own_fingerprint: &[u8]) -> Arc<IntroPointService> {
        Arc::new(IntroPointService {
            own_fingerprint: own_fingerprint.to_vec(),
            services: Mutex::new(HashMap::new()),
            forwarded: AtomicUsize::new(0),
        })
    }

    pub fn bind(self: &Arc<Self>, stack: &PortStack) {
        stack.bind(well_known_ports::INTRO_POINT, self.clone());
    }

    pub fn service_count(&self) -> usize {
        self.services.lock().unwrap().len()
    }
    pub fn forwarded(&self) -> usize {
        self.forwarded.load(Ordering::Relaxed)
    }

    fn establish(&self, stream: &Arc<ServerStream>, body: &[u8]) {
        if body.len() != hp::ESTABLISH_BODY_SIZE {
            stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::BadRequest));
            return;
        }
        // Signed for this very point and recently — not a copy brought from
        // another introduction point.
        let signing_key = match hp::verify_establish(body, &self.own_fingerprint) {
            Some(k) => k,
            None => {
                stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::BadSignature));
                return;
            }
        };

        let id = compute_fingerprint(signing_key).to_vec();
        {
            let mut services = self.services.lock().unwrap();
            if services.len() >= MAX_SERVICES && !services.contains_key(&id) {
                stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::Busy));
                return;
            }
            services.insert(id.clone(), stream.clone());
        }
        stream.set_state(Box::new(id));
        stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::Ok));
    }

    fn introduce(&self, stream: &Arc<ServerStream>, body: &[u8]) {
        if body.len() <= FINGERPRINT_SIZE {
            stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::BadRequest));
            return;
        }
        let fingerprint = body[..FINGERPRINT_SIZE].to_vec();
        let invite = &body[FINGERPRINT_SIZE..];

        let service = self.services.lock().unwrap().get(&fingerprint).cloned();
        let service = match service {
            Some(s) if s.is_open() => s,
            _ => {
                stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::NoService));
                return;
            }
        };

        // Moved blindly: the contents are sealed on the service's key.
        service.send(&hp::message(IntroOp::Forwarded as u8, invite));
        self.forwarded.fetch_add(1, Ordering::Relaxed);
        stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::Ok));
    }
}

impl PortService for IntroPointService {
    fn on_open(&self, _stream: Arc<ServerStream>) -> bool {
        true
    }

    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        let (op, body) = match hp::try_read(data) {
            Some(x) => x,
            None => {
                stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::BadRequest));
                return;
            }
        };
        if op == IntroOp::Establish as u8 {
            self.establish(stream, &body);
        } else if op == IntroOp::Introduce as u8 {
            self.introduce(stream, &body);
        } else {
            stream.send(&hp::ack(IntroOp::Ack as u8, HiddenStatus::BadRequest));
        }
    }

    fn on_close(&self, stream: &Arc<ServerStream>) {
        if let Some(id) = stream.with_state::<Vec<u8>, _>(|id| id.clone()) {
            let mut services = self.services.lock().unwrap();
            if let Some(current) = services.get(&id) {
                if Arc::ptr_eq(current, stream) {
                    services.remove(&id);
                }
            }
        }
        stream.take_state();
    }
}
