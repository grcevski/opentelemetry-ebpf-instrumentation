
mod wire_page_diagnostic {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::ffi::{c_int, c_void};
    use std::ptr;

    struct BoundaryAllocator;
    const BUFFER_SIZE: usize = 8192;
    const BYTES_BEFORE_BOUNDARY: usize = 112;
    const PROT_READ_WRITE: c_int = 3;
    const MAP_PRIVATE_ANONYMOUS: c_int = 0x22;

    unsafe extern "C" {
        fn getpagesize() -> c_int;
        fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
        fn munmap(addr: *mut c_void, len: usize) -> c_int;
    }

    fn is_hyper_buffer(layout: Layout) -> bool {
        layout.size() == BUFFER_SIZE && layout.align() <= 16
    }

    unsafe impl GlobalAlloc for BoundaryAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if !is_hyper_buffer(layout) {
                return unsafe { System.alloc(layout) };
            }
            let page = unsafe { getpagesize() } as usize;
            let start = unsafe { mmap(ptr::null_mut(), page + BUFFER_SIZE, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, -1, 0) };
            if start as isize == -1 {
                return ptr::null_mut();
            }
            unsafe { start.cast::<u8>().add(page - BYTES_BEFORE_BOUNDARY) }
        }

        unsafe fn dealloc(&self, address: *mut u8, layout: Layout) {
            if !is_hyper_buffer(layout) {
                unsafe { System.dealloc(address, layout) };
                return;
            }
            let page = unsafe { getpagesize() } as usize;
            let start = unsafe { address.sub(page - BYTES_BEFORE_BOUNDARY) };
            unsafe { munmap(start.cast(), page + BUFFER_SIZE) };
        }
    }

    #[global_allocator]
    static ALLOCATOR: BoundaryAllocator = BoundaryAllocator;
}
