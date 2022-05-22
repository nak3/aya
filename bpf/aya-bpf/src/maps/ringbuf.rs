use core::{marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_cty::{c_long, c_void};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct PerfEventArray<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> PerfEventArray<T> {
    pub const fn new(flags: u32) -> PerfEventArray<T> {
        PerfEventArray::with_max_entries(0, flags)
    }

    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerfEventArray<T> {
        PerfEventArray {
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

    pub const fn pinned(max_entries: u32, flags: u32) -> PerfEventArray<T> {
        PerfEventArray {
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

    pub fn output<C: BpfContext>(&mut self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: BpfContext>(&mut self, ctx: &C, index: u32, data: &T, flags: u32) {
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
