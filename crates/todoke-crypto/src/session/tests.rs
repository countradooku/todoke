//! Integration tests of the session layers: establishment, crash and
//! rollback policy, the adversarial state machine, and the async adapter.

mod async_io;
mod establishment;
mod state_machine;
pub(crate) mod support;
