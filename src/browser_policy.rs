use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE,
    REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
};

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Menulis nilai REG_SZ ke HKLM\<subkey>\<value_name>
fn set_hklm_string(subkey: &str, value_name: &str, data: &str) -> Result<(), String> {
    unsafe {
        let subkey_w = to_wide_null(subkey);
        let value_w = to_wide_null(value_name);
        let data_w = to_wide_null(data);
        let mut hkey = HKEY::default();

        let create_err = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if create_err.is_err() {
            return Err(format!("RegCreateKeyExW({}) gagal: {:?}", subkey, create_err));
        }

        let byte_slice = std::slice::from_raw_parts(
            data_w.as_ptr() as *const u8,
            data_w.len() * std::mem::size_of::<u16>(),
        );
        let set_err = RegSetValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            0,
            REG_SZ,
            Some(byte_slice),
        );
        let _ = RegCloseKey(hkey);

        if set_err.is_err() {
            return Err(format!(
                "RegSetValueExW({}\\{}) gagal: {:?}",
                subkey, value_name, set_err
            ));
        }
        Ok(())
    }
}

/// Menulis nilai REG_DWORD ke HKLM\<subkey>\<value_name>
fn set_hklm_dword(subkey: &str, value_name: &str, data: u32) -> Result<(), String> {
    unsafe {
        let subkey_w = to_wide_null(subkey);
        let value_w = to_wide_null(value_name);
        let mut hkey = HKEY::default();

        let create_err = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if create_err.is_err() {
            return Err(format!("RegCreateKeyExW({}) gagal: {:?}", subkey, create_err));
        }

        let bytes = data.to_le_bytes();
        let set_err = RegSetValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            0,
            REG_DWORD,
            Some(&bytes),
        );
        let _ = RegCloseKey(hkey);

        if set_err.is_err() {
            return Err(format!(
                "RegSetValueExW({}\\{}) gagal: {:?}",
                subkey, value_name, set_err
            ));
        }
        Ok(())
    }
}

/// Menerapkan kebijakan Enterprise Browser Policy pada Windows Registry (HKLM):
/// 1. Menonaktifkan DNS-over-HTTPS (DoH) pada Google Chrome & Microsoft Edge agar DNS melewati Windows DNS Client.
/// 2. Menonaktifkan mode Incognito (Chrome) & InPrivate (Edge).
pub fn enforce_enterprise_browser_policies() {
    let chrome_key = r"SOFTWARE\Policies\Google\Chrome";
    let edge_key = r"SOFTWARE\Policies\Microsoft\Edge";

    let mut applied = 0usize;
    let mut failed = 0usize;

    let ops: [(&str, Result<(), String>); 4] = [
        ("Chrome DnsOverHttpsMode=off", set_hklm_string(chrome_key, "DnsOverHttpsMode", "off")),
        ("Chrome IncognitoModeAvailability=1", set_hklm_dword(chrome_key, "IncognitoModeAvailability", 1)),
        ("Edge DnsOverHttpsMode=off", set_hklm_string(edge_key, "DnsOverHttpsMode", "off")),
        ("Edge InPrivateModeAvailability=1", set_hklm_dword(edge_key, "InPrivateModeAvailability", 1)),
    ];

    for (label, res) in ops {
        match res {
            Ok(_) => applied += 1,
            Err(e) => {
                failed += 1;
                warn!("Browser policy [{}] gagal diterapkan (butuh LocalSystem/Administrator): {}", label, e);
            }
        }
    }

    if applied > 0 && failed == 0 {
        info!("Enterprise Browser Policy aktif ({} kebijakan HKLM diterapkan untuk Chrome & Edge: DoH=off, Incognito/InPrivate=disabled).", applied);
    } else if applied > 0 {
        warn!("Enterprise Browser Policy diterapkan sebagian: {} berhasil, {} gagal.", applied, failed);
    }
}
