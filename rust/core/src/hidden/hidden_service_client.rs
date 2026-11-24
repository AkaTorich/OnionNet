//! The guest's side: how to reach a service without knowing where it is.
//!
//! The order is this. We take a meeting point with a random token. We go to the
//! service's introduction point and hand over a sealed invitation saying where to
//! wait for us. The service comes there over a circuit of its own, and the
//! meeting point stitches the two ends together.
//!
//! The introduction point does not know which meeting point we chose: the
//! invitation is sealed on the service's key. The meeting point does not know who
//! we are or who the service is: it holds only two ends of two circuits that are
//! none of its business.
//!
//! DECOUPLING FROM C#: the caller passes the service's announcement in rather
//! than the client looking it up, so this module does not depend on the Peers
//! directory. Everything else matches `HiddenServiceClient` byte for byte.

use crate::crypto::rand;
use crate::hidden::circuit_factory::CircuitFactory;
use crate::hidden::e2e_channel::E2EChannel;
use crate::hidden::e2e_session::E2ESession;
use crate::hidden::hidden_protocol::{self as hp, HiddenStatus, IntroOp, RendezvousOp, COOKIE_SIZE};
use crate::hidden::service_descriptor::ServiceDescriptor;
use crate::identity::onion_address::{OnionAddress, FINGERPRINT_SIZE};
use crate::protocol::ntor;
use crate::streams::message_channel::MessageChannel;
use crate::streams::multiplexed_circuit::MultiplexedCircuit;
use crate::streams::stream_payloads::well_known_ports;
use crate::text::t;
use std::sync::Arc;
use std::time::Duration;

/// The default wait for each round trip to a point.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(45);

/// The hidden service could not be reached. (The C# `HiddenServiceException`.)
#[derive(Debug, Clone)]
pub struct HiddenServiceError(pub String);

impl std::fmt::Display for HiddenServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for HiddenServiceError {}

fn err<T>(message: impl Into<String>) -> Result<T, HiddenServiceError> {
    Err(HiddenServiceError(message.into()))
}

/// Reaches a hidden service through its announcement and returns the finished
/// end-to-end channel, with the default per-round-trip wait.
pub fn connect_default(
    address: &OnionAddress,
    descriptor: &ServiceDescriptor,
    factory: &mut CircuitFactory,
) -> Result<E2EChannel, HiddenServiceError> {
    connect(address, descriptor, factory, DEFAULT_WAIT)
}

/// Reaches a hidden service through its announcement and returns the finished
/// end-to-end channel.
pub fn connect(
    address: &OnionAddress,
    descriptor: &ServiceDescriptor,
    factory: &mut CircuitFactory,
    wait: Duration,
) -> Result<E2EChannel, HiddenServiceError> {
    // The announcement must belong to exactly the address we were heading for.
    // Otherwise a keeper would slip in an announcement of its own service
    // instead of somebody else's.
    if !descriptor.matches(address) {
        return err("the announcement belongs to a different address");
    }

    // 1. We take a meeting point — any node that is not one of the service's
    // introduction points.
    let exclude: Vec<Vec<u8>> = descriptor.intro_points.iter().map(|fp| fp.to_vec()).collect();
    let rendezvous = match factory.pick_random(&exclude) {
        Some(r) => r,
        None => return err("there is no free node for a meeting point"),
    };

    let cookie_bytes = rand::get_bytes(COOKIE_SIZE);
    let mut cookie = [0u8; COOKIE_SIZE];
    cookie.copy_from_slice(&cookie_bytes);

    let rendezvous_circuit = factory.build_to(&rendezvous).map_err(|e| HiddenServiceError(e.to_string()))?;

    let rendezvous_stream = match rendezvous_circuit.open(well_known_ports::RENDEZVOUS) {
        Some(s) => s,
        None => return err(format!("node {} does not run a meeting point", rendezvous.nickname)),
    };

    rendezvous_stream.send(&hp::message(RendezvousOp::Establish as u8, &cookie));

    let ack = rendezvous_stream.receive(wait);
    if !is_ok(&ack, RendezvousOp::Ack as u8) {
        return err(format!("the meeting point refused: {}", reason(&ack)));
    }

    // 2. We prepare the handshake with the service itself. The service's
    // fingerprint here is its address — as with an ordinary relay.
    let handshake = ntor::begin_client(&descriptor.fingerprint(), &descriptor.onion_key)
        .map_err(|e| HiddenServiceError(e.to_string()))?;

    let invite = hp::seal_invite(
        &descriptor.onion_key,
        &rendezvous.fingerprint(),
        &cookie,
        handshake.message(),
    )
    .map_err(|e| HiddenServiceError(e.to_string()))?;

    // 3. We hand the invitation over through the introduction point. The circuit
    // to it was needed for one invitation only; it is dropped when this returns.
    let _intro_circuit = match send_invite(descriptor, factory, &invite, wait) {
        Some(c) => c,
        None => return err("not one introduction point took the invitation"),
    };

    // 4. We wait for the service to come to the meeting.
    let joined = match rendezvous_stream.receive(wait) {
        Some(j) => j,
        None => return err("the service did not come to the meeting"),
    };

    let (op, body) = match hp::try_read(&joined) {
        Some(parsed) => parsed,
        None => return err("the meeting point answered beside the point"),
    };
    if op != RendezvousOp::Joined as u8 {
        return err("the meeting point answered beside the point");
    }

    let mut material = match handshake.complete(&body) {
        Some(m) => m,
        None => return err("the service did not prove its key — that is not it at the far end"),
    };

    let session = E2ESession::create(&material, true);
    rand::wipe(&mut material);

    // Ownership of the rendezvous circuit passes to the channel.
    let channel = E2EChannel::new(
        rendezvous_stream as Arc<dyn MessageChannel>,
        rendezvous_circuit,
        session,
        true,
    );
    Ok(channel)
}

/// Tries the introduction points in turn until one takes the invitation.
/// Returns the circuit to that introduction point (to be dropped by the caller).
fn send_invite(
    descriptor: &ServiceDescriptor,
    factory: &mut CircuitFactory,
    invite: &[u8],
    wait: Duration,
) -> Option<MultiplexedCircuit> {
    for fingerprint in &descriptor.intro_points {
        let relay = match factory.find(fingerprint) {
            Some(r) => r,
            None => continue,
        };

        let attempt = match factory.build_to(&relay) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let stream = match attempt.open(well_known_ports::INTRO_POINT) {
            Some(s) => s,
            None => continue, // `attempt` drops here
        };

        let mut body = Vec::with_capacity(FINGERPRINT_SIZE + invite.len());
        body.extend_from_slice(&descriptor.fingerprint());
        body.extend_from_slice(invite);

        stream.send(&hp::message(IntroOp::Introduce as u8, &body));

        let ack = stream.receive(wait);
        if !is_ok(&ack, IntroOp::Ack as u8) {
            continue; // `attempt` drops here
        }

        return Some(attempt);
    }

    None
}

fn is_ok(answer: &Option<Vec<u8>>, expected_op: u8) -> bool {
    match answer {
        Some(a) => a.len() >= 2 && a[0] == expected_op && a[1] == HiddenStatus::Ok as u8,
        None => false,
    }
}

fn reason(answer: &Option<Vec<u8>>) -> String {
    match answer {
        None => t("hidden.reason.silent"),
        Some(a) if a.len() < 2 => t("hidden.reason.silent"),
        Some(a) => match HiddenStatus::from_u8(a[1]) {
            Some(status) => status.explain(),
            None => t("hidden.reason.unclear"),
        },
    }
}
