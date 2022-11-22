/* automatically generated by rust-bindgen 0.61.0 */

pub type __u8 = ::std::os::raw::c_uchar;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __u32 = ::std::os::raw::c_uint;
pub mod bpf_core_relo_kind {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPF_CORE_FIELD_BYTE_OFFSET: Type = 0;
    pub const BPF_CORE_FIELD_BYTE_SIZE: Type = 1;
    pub const BPF_CORE_FIELD_EXISTS: Type = 2;
    pub const BPF_CORE_FIELD_SIGNED: Type = 3;
    pub const BPF_CORE_FIELD_LSHIFT_U64: Type = 4;
    pub const BPF_CORE_FIELD_RSHIFT_U64: Type = 5;
    pub const BPF_CORE_TYPE_ID_LOCAL: Type = 6;
    pub const BPF_CORE_TYPE_ID_TARGET: Type = 7;
    pub const BPF_CORE_TYPE_EXISTS: Type = 8;
    pub const BPF_CORE_TYPE_SIZE: Type = 9;
    pub const BPF_CORE_ENUMVAL_EXISTS: Type = 10;
    pub const BPF_CORE_ENUMVAL_VALUE: Type = 11;
    pub const BPF_CORE_TYPE_MATCHES: Type = 12;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_core_relo {
    pub insn_off: __u32,
    pub type_id: __u32,
    pub access_str_off: __u32,
    pub kind: bpf_core_relo_kind::Type,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_ext_header {
    pub magic: __u16,
    pub version: __u8,
    pub flags: __u8,
    pub hdr_len: __u32,
    pub func_info_off: __u32,
    pub func_info_len: __u32,
    pub line_info_off: __u32,
    pub line_info_len: __u32,
    pub core_relo_off: __u32,
    pub core_relo_len: __u32,
}
