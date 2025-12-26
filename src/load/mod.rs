#[cfg(feature = "load_payload_embedded")]
pub mod embedded;
#[cfg(feature = "load_payload_separate")]
pub mod separate;

#[cfg(feature = "load_payload_embedded")]
pub use embedded::load;
#[cfg(feature = "load_payload_separate")]
pub use separate::load;