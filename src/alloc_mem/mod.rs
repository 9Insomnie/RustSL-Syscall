#[cfg(feature = "alloc_mem_nt_allocate_virtual_memory")]
mod nt_allocate_virtual_memory;
#[cfg(feature = "alloc_mem_nt_allocate_virtual_memory")]
pub use crate::alloc_mem::nt_allocate_virtual_memory::alloc_mem;

#[cfg(feature = "alloc_mem_nt_map_view_of_section")]
mod nt_map_view_of_section;
#[cfg(feature = "alloc_mem_nt_map_view_of_section")]
pub use crate::alloc_mem::nt_map_view_of_section::alloc_mem;