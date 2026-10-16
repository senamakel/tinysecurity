//! Native `TinyBus` ABI adapter for the conservative security bootstrap.
//!
//! Initialize through the SDK with [`tinysecurity_bus::ModuleConfig`]. Hosts
//! depend only on the transport-free contract, never this implementation.
mod adapter;

mod callbacks;

mod approval_callbacks;

mod secret_callbacks;

mod stream_pins;
