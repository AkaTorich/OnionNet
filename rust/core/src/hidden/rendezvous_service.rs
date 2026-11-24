//! A meeting point: the node where the client's circuit and the service's
//! circuit come together.
//!
//! The client takes a place with a random token and waits. The service arrives
//! with the same token, and from then on the meeting point simply moves bytes
//! from one circuit into the other, understanding nothing — the contents are
//! under the two sides' end-to-end cipher.

use crate::hidden::hidden_protocol::{self as hp, HiddenStatus, RendezvousOp, COOKIE_SIZE};
use crate::streams::port_stack::{PortService, PortStack, ServerStream};
use crate::streams::stream_end_reason::StreamEndReason;
use crate::streams::stream_payloads::well_known_ports;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// One node holds no more simultaneous meetings than this.
pub const MAX_PENDING: usize = 256;

/// The state of one end of a meeting.
#[derive(Default)]
struct Meeting {
    cookie: Mutex<Option<Vec<u8>>>,
    partner: Mutex<Option<Arc<ServerStream>>>,
}

#[derive(Default)]
pub struct RendezvousService {
    waiting: Mutex<HashMap<Vec<u8>, Arc<ServerStream>>>,
    joined: AtomicUsize,
}

impl RendezvousService {
    pub fn new() -> Arc<RendezvousService> {
        Arc::new(RendezvousService::default())
    }

    pub fn bind(self: &Arc<Self>, stack: &PortStack) {
        stack.bind(well_known_ports::RENDEZVOUS, self.clone());
    }

    pub fn waiting_count(&self) -> usize {
        self.waiting.lock().unwrap().len()
    }
    pub fn joined_count(&self) -> usize {
        self.joined.load(Ordering::Relaxed)
    }

    fn meeting_of(stream: &Arc<ServerStream>) -> Option<Arc<Meeting>> {
        stream.with_state::<Arc<Meeting>, _>(|m| m.clone())
    }

    fn establish(&self, stream: &Arc<ServerStream>, meeting: &Meeting, body: &[u8]) {
        if body.len() != COOKIE_SIZE || meeting.cookie.lock().unwrap().is_some() {
            stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::BadRequest));
            return;
        }
        let cookie = body.to_vec();
        {
            let mut waiting = self.waiting.lock().unwrap();
            if waiting.contains_key(&cookie) {
                stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::Taken));
                return;
            }
            if waiting.len() >= MAX_PENDING {
                stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::Busy));
                return;
            }
            waiting.insert(cookie.clone(), stream.clone());
        }
        *meeting.cookie.lock().unwrap() = Some(cookie);
        stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::Ok));
    }

    fn join(&self, stream: &Arc<ServerStream>, meeting: &Meeting, body: &[u8]) {
        if body.len() <= COOKIE_SIZE {
            stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::BadRequest));
            return;
        }
        let cookie = body[..COOKIE_SIZE].to_vec();
        let payload = &body[COOKIE_SIZE..];

        let client = {
            // The token is single-use: a second taker will not come.
            self.waiting.lock().unwrap().remove(&cookie)
        };
        let client = match client {
            Some(c) => c,
            None => {
                stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::NoRendezvous));
                return;
            }
        };
        let client_meeting = match RendezvousService::meeting_of(&client) {
            Some(m) if client.is_open() => m,
            _ => {
                stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::NoRendezvous));
                return;
            }
        };

        *client_meeting.cookie.lock().unwrap() = None;
        *client_meeting.partner.lock().unwrap() = Some(stream.clone());
        *meeting.partner.lock().unwrap() = Some(client.clone());
        self.joined.fetch_add(1, Ordering::Relaxed);

        // The second half of the handshake goes to the client; after that it is
        // an end-to-end channel.
        client.send(&hp::message(RendezvousOp::Joined as u8, payload));
    }
}

impl PortService for RendezvousService {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        stream.set_state(Box::new(Arc::new(Meeting::default())));
        true
    }

    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        let meeting = match RendezvousService::meeting_of(stream) {
            Some(m) => m,
            None => return,
        };

        // Once joined, there is only moving.
        {
            let partner = meeting.partner.lock().unwrap();
            if let Some(partner) = partner.as_ref() {
                if partner.is_open() {
                    partner.send(data);
                }
                return;
            }
        }

        let (op, body) = match hp::try_read(data) {
            Some(x) => x,
            None => {
                stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::BadRequest));
                return;
            }
        };
        if op == RendezvousOp::Establish as u8 {
            self.establish(stream, &meeting, &body);
        } else if op == RendezvousOp::Join as u8 {
            self.join(stream, &meeting, &body);
        } else {
            stream.send(&hp::ack(RendezvousOp::Ack as u8, HiddenStatus::BadRequest));
        }
    }

    fn on_close(&self, stream: &Arc<ServerStream>) {
        let meeting = match RendezvousService::meeting_of(stream) {
            Some(m) => m,
            None => return,
        };

        let cookie = meeting.cookie.lock().unwrap().take();
        if let Some(cookie) = cookie {
            let mut waiting = self.waiting.lock().unwrap();
            if let Some(current) = waiting.get(&cookie) {
                if Arc::ptr_eq(current, stream) {
                    waiting.remove(&cookie);
                }
            }
        }

        // A meeting is for two: one left, the other has nothing to do here.
        let partner = meeting.partner.lock().unwrap().take();
        if let Some(partner) = partner {
            if let Some(partner_meeting) = RendezvousService::meeting_of(&partner) {
                *partner_meeting.partner.lock().unwrap() = None;
            }
            partner.close(StreamEndReason::Done);
        }
        stream.take_state();
    }
}
