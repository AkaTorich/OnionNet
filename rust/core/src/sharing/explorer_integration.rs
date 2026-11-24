//! Our own item in a folder's context menu, next to "Give access to" (the C#
//! `ExplorerIntegration`).
//!
//! ## Cross-platform shape
//!
//! This is a Windows shell integration done purely with `HKCU` registry entries —
//! no COM extension, no administrator rights. There is no equivalent on other
//! platforms, so every operation is a graceful no-op there: [`register`] does
//! nothing and succeeds, [`is_registered`] is `false`, [`describe`] is empty.
//!
//! On Windows the real registry writes are gated behind `#[cfg(all(windows,
//! feature = "windows_explorer"))]` because they need a `windows-sys` namespace
//! feature this crate does not yet enable (see the port report). Until then even a
//! Windows build is a no-op rather than a broken build.

use crate::text::t;

/// The menu key for the current user's folders.
pub const DEFAULT_ROOT_KEY: &str = r"Software\Classes\Directory\shell\StalkNet";

/// One entry of the cascading submenu: its key name, its title key, and the verb
/// passed to the application. Used only by the gated Windows backend.
#[allow(dead_code)]
struct MenuItem {
    key_name: &'static str,
    title_key: &'static str,
    verb: &'static str,
}

#[allow(dead_code)]
const ITEMS: &[MenuItem] = &[
    MenuItem { key_name: "01publish", title_key: "explorer.publish", verb: "publish" },
    MenuItem { key_name: "02unpublish", title_key: "explorer.unpublish", verb: "unpublish" },
    MenuItem { key_name: "03address", title_key: "explorer.address", verb: "address" },
    MenuItem { key_name: "04guests", title_key: "explorer.guests", verb: "guests" },
];

#[allow(dead_code)]
fn menu_title() -> String {
    t("explorer.menu")
}

/// Whether the context-menu item is installed. Always `false` where the shell
/// integration does not apply.
pub fn is_registered(root_key: Option<&str>) -> bool {
    is_registered_impl(root_key.unwrap_or(DEFAULT_ROOT_KEY))
}

/// Writes the cascading submenu. Every item calls our application and passes it
/// the folder's path through `%1`. A no-op (returning `Ok`) where the shell
/// integration does not apply.
pub fn register(executable_path: &str, root_key: Option<&str>) -> Result<(), String> {
    if executable_path.is_empty() {
        return Err("No path to the application was given.".to_string());
    }
    register_impl(executable_path, root_key.unwrap_or(DEFAULT_ROOT_KEY))
}

/// Removes the submenu entirely. Quietly tolerates a missing key, and is a no-op
/// where the shell integration does not apply.
pub fn unregister(root_key: Option<&str>) -> Result<(), String> {
    unregister_impl(root_key.unwrap_or(DEFAULT_ROOT_KEY))
}

/// What is written there now — for checking and for showing to the owner. Empty
/// where the shell integration does not apply.
pub fn describe(root_key: Option<&str>) -> Vec<String> {
    describe_impl(root_key.unwrap_or(DEFAULT_ROOT_KEY))
}

// ---- The portable no-op backend ----------------------------------------------

#[cfg(not(all(windows, feature = "windows_explorer")))]
fn is_registered_impl(_root_key: &str) -> bool {
    false
}

#[cfg(not(all(windows, feature = "windows_explorer")))]
fn register_impl(_executable_path: &str, _root_key: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(all(windows, feature = "windows_explorer")))]
fn unregister_impl(_root_key: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(all(windows, feature = "windows_explorer")))]
fn describe_impl(_root_key: &str) -> Vec<String> {
    Vec::new()
}

// ---- The real Windows backend (gated, unverified until its features land) ------
//
// Ports the HKCU registry writes of `ExplorerIntegration`. Compiled only under
// `#[cfg(all(windows, feature = "windows_explorer"))]`. To enable it the main
// thread must add a crate feature `windows_explorer` and extend the windows-sys
// features with "Win32_System_Registry" (RegCreateKeyExW, RegSetValueExW,
// RegDeleteTreeW, RegOpenKeyExW, RegCloseKey).
#[cfg(all(windows, feature = "windows_explorer"))]
mod registry {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Creates (or opens) a subkey of HKCU. The caller closes the handle.
    fn create_key(path: &str) -> Option<HKEY> {
        let wide = to_wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut key as *mut HKEY,
                std::ptr::null_mut(),
            )
        };
        if rc == ERROR_SUCCESS {
            Some(key)
        } else {
            None
        }
    }

    fn set_string(key: HKEY, name: &str, value: &str) {
        let name_w = to_wide(name);
        let value_w = to_wide(value);
        let bytes = value_w.len() * std::mem::size_of::<u16>();
        unsafe {
            RegSetValueExW(
                key,
                name_w.as_ptr(),
                0,
                REG_SZ,
                value_w.as_ptr() as *const u8,
                bytes as u32,
            );
        }
    }

    pub(super) fn is_registered(root_key: &str) -> bool {
        let wide = to_wide(root_key);
        let mut key: HKEY = std::ptr::null_mut();
        let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide.as_ptr(), 0, KEY_READ, &mut key as *mut HKEY) };
        if rc == ERROR_SUCCESS {
            unsafe { RegCloseKey(key) };
            true
        } else {
            false
        }
    }

    pub(super) fn register(executable_path: &str, root: &str) -> Result<(), String> {
        let key = create_key(root).ok_or_else(|| format!("The key {} could not be created", root))?;
        set_string(key, "MUIVerb", &menu_title());
        // An empty SubCommands tells the shell to take the submenu items from the
        // nested shell key rather than from a list of names.
        set_string(key, "SubCommands", "");
        if std::path::Path::new(executable_path).exists() {
            set_string(key, "Icon", &format!("{},0", executable_path));
        }
        unsafe { RegCloseKey(key) };

        for item in ITEMS {
            let item_path = format!(r"{}\shell\{}", root, item.key_name);
            if let Some(item_key) = create_key(&item_path) {
                set_string(item_key, "MUIVerb", &t(item.title_key));
                unsafe { RegCloseKey(item_key) };
            }
            let command_path = format!(r"{}\command", item_path);
            if let Some(command_key) = create_key(&command_path) {
                set_string(command_key, "", &format!("\"{}\" {} \"%1\"", executable_path, item.verb));
                unsafe { RegCloseKey(command_key) };
            }
        }
        Ok(())
    }

    pub(super) fn unregister(root: &str) -> Result<(), String> {
        let wide = to_wide(root);
        // RegDeleteTreeW tolerates a missing key with ERROR_FILE_NOT_FOUND.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, wide.as_ptr()) };
        Ok(())
    }

    pub(super) fn describe(root: &str) -> Vec<String> {
        if !is_registered(root) {
            return Vec::new();
        }
        // A minimal description built from the configured items (reading every
        // value back would need far more read FFI for no extra truth, since we
        // wrote them). Flagged as simplified in the port report.
        let mut lines = vec![menu_title()];
        for item in ITEMS {
            lines.push(format!("    {}  ->  {}", t(item.title_key), item.verb));
        }
        lines
    }
}

#[cfg(all(windows, feature = "windows_explorer"))]
fn is_registered_impl(root_key: &str) -> bool {
    registry::is_registered(root_key)
}

#[cfg(all(windows, feature = "windows_explorer"))]
fn register_impl(executable_path: &str, root_key: &str) -> Result<(), String> {
    registry::register(executable_path, root_key)
}

#[cfg(all(windows, feature = "windows_explorer"))]
fn unregister_impl(root_key: &str) -> Result<(), String> {
    registry::unregister(root_key)
}

#[cfg(all(windows, feature = "windows_explorer"))]
fn describe_impl(root_key: &str) -> Vec<String> {
    registry::describe(root_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_needs_an_executable_path() {
        assert!(register("", None).is_err());
    }

    #[test]
    fn portable_backend_is_a_graceful_noop() {
        // On non-Windows, and on Windows without the feature, nothing is installed.
        #[cfg(not(all(windows, feature = "windows_explorer")))]
        {
            assert!(!is_registered(None));
            assert!(register("app.exe", None).is_ok());
            assert!(unregister(None).is_ok());
            assert!(describe(None).is_empty());
        }
    }
}
