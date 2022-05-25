use core::{marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{bpf_ringbuf_output},
    maps::PinningType,
    BpfContext,
};

#[repr(transparent)]
pub struct Ringbuf<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> Ringbuf<T> {
    pub const fn new(flags: u32) -> Ringbuf<T> {
        Ringbuf::with_max_entries(0, flags)
    }

    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Ringbuf<T> {
        Ringbuf {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Ringbuf<T> {
        Ringbuf {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
            _t: PhantomData,
        }
    }

    // No index is fine.
    pub fn output<C: BpfContext>(&mut self, ctx: &C, data: &T, flags: u32) {
        let flags = (flags as u64) << 32 | index as u64;
        unsafe {
            bpf_ringbuf_output(
                ctx.as_ptr(),
                &mut self.def as *mut _ as *mut _,
                flags,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
            );
        }
    }
}
