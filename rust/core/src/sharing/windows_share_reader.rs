//! Reads the machine's SMB shares — the ones made through "Give access to /
//! Specific people" (the C# `WindowsShareReader`, which used WMI).
//!
//! ## Cross-platform shape
//!
//! On non-Windows there are no SMB shares to read, so [`enumerate`] returns an
//! empty list and the catalogue works from the manual list alone.
//!
//! On Windows the real reader uses `NetShareEnum` (netapi32), not WMI — no WMI
//! crate is pulled in. It is gated behind `#[cfg(all(windows, feature =
//! "windows_shares"))]` because `NetShareEnum` needs a `windows-sys` namespace
//! feature this crate does not yet enable (see the port report). Until the feature
//! is turned on, even a Windows build returns an empty list rather than breaking.
//!
//! Administrative shares (C$, ADMIN$, IPC$) are sieved out: they are on every
//! machine always and mean the exact opposite of publishing.

use super::shared_folder::SharedFolder;

/// The folders published on this machine, or an empty list if they cannot be read
/// (or on a platform without SMB shares).
pub fn enumerate() -> Vec<SharedFolder> {
    enumerate_impl()
}

#[cfg(all(windows, feature = "windows_shares"))]
fn enumerate_impl() -> Vec<SharedFolder> {
    windows_shares::enumerate()
}

#[cfg(not(all(windows, feature = "windows_shares")))]
fn enumerate_impl() -> Vec<SharedFolder> {
    Vec::new()
}

/// Whether a share name is administrative (ends with `$`), which is never
/// published. Pure text, so it is tested on every platform (used by the gated
/// Windows backend; also exercised by the unit test).
#[allow(dead_code)]
pub(crate) fn is_administrative(share_name: &str) -> bool {
    share_name.is_empty() || share_name.ends_with('$')
}

// ---- The real Windows reader (gated, unverified until its features land) ------
//
// Ports the enumeration of `WindowsShareReader`. Compiled only under
// `#[cfg(all(windows, feature = "windows_shares"))]`. To enable it the main thread
// must add a crate feature `windows_shares` and extend the windows-sys features
// with "Win32_NetworkManagement_NetManagement" (NetShareEnum, NetApiBufferFree,
// SHARE_INFO_2).
#[cfg(all(windows, feature = "windows_shares"))]
mod windows_shares {
    use super::*;
    use crate::sharing::shared_folder::{ShareAccess, ShareOrigin};
    use windows_sys::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetShareEnum, SHARE_INFO_2};

    /// `STYPE_DISKTREE` — an ordinary disk folder. The special shares have high
    /// bits set (`STYPE_SPECIAL` 0x8000_0000, `STYPE_TEMPORARY` 0x4000_0000), so
    /// only the low byte is compared, as the C# did against `Type = 0`.
    const STYPE_DISKTREE: u32 = 0;
    const STYPE_MASK: u32 = 0x0000_00FF;
    const MAX_PREFERRED_LENGTH: u32 = 0xFFFF_FFFF;
    const NERR_SUCCESS: u32 = 0;

    fn from_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    /// Enumerates the local machine's disk shares at level 2 (which carries the
    /// on-disk path). Mirrors the C# `TryEnumerate`: skip non-disk and
    /// administrative shares, and quietly return what was read on any failure.
    pub(super) fn enumerate() -> Vec<SharedFolder> {
        let mut result: Vec<SharedFolder> = Vec::new();

        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = unsafe {
            NetShareEnum(
                std::ptr::null(),
                2,
                &mut buffer as *mut *mut u8,
                MAX_PREFERRED_LENGTH,
                &mut entries_read as *mut u32,
                &mut total_entries as *mut u32,
                std::ptr::null_mut(),
            )
        };

        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                unsafe { NetApiBufferFree(buffer as *mut _) };
            }
            return result;
        }

        let infos = buffer as *const SHARE_INFO_2;
        for i in 0..entries_read as usize {
            let info = unsafe { &*infos.add(i) };
            if info.shi2_type & STYPE_MASK != STYPE_DISKTREE {
                continue;
            }

            let name = from_wide(info.shi2_netname);
            if is_administrative(&name) {
                continue;
            }

            let path = from_wide(info.shi2_path);
            if path.is_empty() {
                continue;
            }

            if let Ok(mut folder) = SharedFolder::new(&path, &name, ShareAccess::WindowsAccounts, ShareOrigin::Windows) {
                folder.set_windows_share_name(Some(name));
                result.push(folder);
            }
        }

        unsafe { NetApiBufferFree(buffer as *mut _) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrative_shares_are_recognised() {
        assert!(is_administrative("C$"));
        assert!(is_administrative("ADMIN$"));
        assert!(is_administrative("IPC$"));
        assert!(is_administrative(""));
        assert!(!is_administrative("Documents"));
    }

    #[test]
    fn enumerate_is_empty_without_the_windows_backend() {
        // On non-Windows, and on Windows without the `windows_shares` feature.
        #[cfg(not(all(windows, feature = "windows_shares")))]
        assert!(enumerate().is_empty());
    }
}
