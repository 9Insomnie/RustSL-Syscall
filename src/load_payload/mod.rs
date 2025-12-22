#[cfg(feature = "load_payload_read_file")]
pub mod read_file;
#[cfg(feature = "load_payload_separate")]
pub mod separate;

#[cfg(feature = "load_payload_read_file")]
pub use read_file::load_payload;
#[cfg(feature = "load_payload_separate")]
pub use separate::load_payload;