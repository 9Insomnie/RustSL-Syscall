#[cfg(feature = "load_payload_read_file")]
pub mod embedded;
#[cfg(feature = "load_payload_separate")]
pub mod separate;

#[cfg(feature = "load_payload_read_file")]
pub use embedded::load;
#[cfg(feature = "load_payload_separate")]
pub use separate::load;