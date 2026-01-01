use std::ptr::null_mut;
use crate::ntapi::close_handle;

pub struct Handle(*mut std::ffi::c_void);

impl Handle {
    pub fn new(handle: *mut std::ffi::c_void) -> Self {
        Self(handle)
    }

    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.0
    }

    pub fn is_invalid(&self) -> bool {
        self.0.is_null() || self.0 == -1isize as *mut std::ffi::c_void
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.is_invalid() {
            close_handle(self.0 as isize);
        }
    }
}

impl From<*mut std::ffi::c_void> for Handle {
    fn from(handle: *mut std::ffi::c_void) -> Self {
        Self::new(handle)
    }
}

impl From<isize> for Handle {
    fn from(handle: isize) -> Self {
        Self::new(handle as *mut std::ffi::c_void)
    }
}
