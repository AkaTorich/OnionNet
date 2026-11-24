//! A finished connection to a hidden service — as the guest sees it.
//!
//! Inside there is one meeting and one end-to-end channel, and over them the same
//! internal ports an ordinary node has. So the folders and the forwarded ports
//! both travel over one meeting: setting up a new meeting per connection would be
//! six hops wasted.
//!
//! DECOUPLING FROM C#: the announcement is passed in (the caller found it), so
//! this module does not depend on the Peers directory.

use crate::hidden::circuit_factory::CircuitFactory;
use crate::hidden::hidden_mux::HiddenMux;
use crate::hidden::hidden_service_client::{self, HiddenServiceError};
use crate::hidden::service_descriptor::ServiceDescriptor;
use crate::identity::onion_address::OnionAddress;
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_opener::StreamOpener;
use std::sync::Arc;
use std::time::Duration;

/// A finished connection to a hidden service (the C# `HiddenConnection`).
pub struct HiddenConnection {
    address: OnionAddress,
    mux: HiddenMux,
}

impl HiddenConnection {
    /// Reaches the service and opens the port multiplexer over the meeting.
    pub fn connect(
        address: &OnionAddress,
        announcement: &ServiceDescriptor,
        factory: &mut CircuitFactory,
        wait: Duration,
    ) -> Result<HiddenConnection, HiddenServiceError> {
        let channel = hidden_service_client::connect(address, announcement, factory, wait)?;
        let mux = HiddenMux::new(Arc::new(channel));
        mux.set_open_timeout(wait);
        Ok(HiddenConnection {
            address: address.clone(),
            mux,
        })
    }

    pub fn address(&self) -> &OnionAddress {
        &self.address
    }

    pub fn is_alive(&self) -> bool {
        self.mux.is_alive()
    }

    /// How many streams travel over this meeting right now.
    pub fn stream_count(&self) -> usize {
        self.mux.stream_count()
    }

    /// Opens a stream to an internal port of the service.
    pub fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>> {
        self.mux.open(port)
    }
}

impl StreamOpener for HiddenConnection {
    fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>> {
        self.mux.open(port)
    }
    fn is_alive(&self) -> bool {
        self.mux.is_alive()
    }
}
