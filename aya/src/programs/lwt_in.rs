//! LWT_IN programs.
use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_LWT_IN,
    obj::btf::{Btf, BtfKind},
    programs::{
        define_link_wrapper, load_program, utils::attach_raw_tracepoint, FdLink, FdLinkId,
        ProgramData, ProgramError,
    },
};

use crate::programs::RawFd;


use crate::{
    generated::{
        bpf_attach_type::{self, BPF_LWT_IN},
        bpf_link_type,
    },
    programs::{
        define_link_wrapper, load_program, FdLink, Link, LinkError, ProgramData, ProgramError,
    },
    sys::{
        bpf_link_create, bpf_link_get_info_by_fd, bpf_link_update, kernel_version,
        netlink_set_xdp_fd,
    },
};


/// A program that attaches to Linux LSM hooks. Used to implement security policy and
/// audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement mandatory
/// access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
/// In order for the probes to fire, you also need the BPF LSM to be enabled through your
/// kernel's boot paramters (like `lsm=lockdown,yama,bpf`).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.7.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum LsmError {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError),
/// # }
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::Lsm, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut Lsm = bpf.program_mut("lsm_prog").unwrap().try_into()?;
/// program.load("security_bprm_exec", &btf)?;
/// program.attach()?;
/// # Ok::<(), LsmError>(())
/// ```
///
/// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_LWT_IN")]
pub struct LwtIn {
    pub(crate) data: ProgramData<LwtInLink>,
}

/// Errors from LWT_IN programs
#[derive(Debug, Error)]
pub enum LwtInError {
    /// netlink error while attaching ebpf program
    #[error("netlink error while attaching ebpf program to tc")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: io::Error,
    },
    /// the clsact qdisc is already attached
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
}


impl LwtIn {
    /// Loads the program inside the kernel.
    ///
    /// # Arguments
    ///
    /// * `lsm_hook_name` - full name of the LSM hook that the program should
    ///   be attached to
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_LWT_IN, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [Lsm::detach].
    pub fn attach(
        &mut self,
        interface: &str,
        attach_type: LwtInAttachType,
        priority: u16,
    ) -> Result<LwtInLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let c_interface = CString::new(interface).unwrap();
        let if_index = ifindex_from_ifname(interface)
            .map_err(|io_error| LwtInError::NetlinkError { io_error })?;

        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }

        let k_ver = kernel_version().unwrap();

            let link_fd = bpf_link_create(prog_fd, if_index, BPF_LWT_IN, None, flags.bits).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create".to_owned(),
                    io_error,
                },
            )? as RawFd;
            self.data
                .links
                .insert(LwtInLink(LwtInLinkInner::FdLink(FdLink::new(link_fd))))
    }

    /// Detaches the program.
    ///
    /// See [LwtIn::attach].
    pub fn detach(&mut self, link_id: LwtInLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: LwtInLinkId) -> Result<LwtInLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [Lsm] programs.
    LwtInLink,
    /// The type returned by [Lsm::attach]. Can be passed to [Lsm::detach].
    LwtInLinkId,
    FdLink,
    FdLinkId
);
