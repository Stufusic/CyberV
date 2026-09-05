//! Windows DPAPI-Protected Vault Storage
//!
//! Ref: rv4.md #4, #5:
//! "CryptProtectData / CryptUnprotectData của Windows...
//! STABLE STORAGE KEY -> identity.vault...
//! Thay RAM/SSD thì vault vẫn mở được bình thường, không làm mất Private Key."

use super::error::StorageError;
use super::models::PersistedIdentity;
use super::DeviceSecureStorage;
use std::fs;
use std::path::{Path, PathBuf};

/// Storage provider backed by Windows Data Protection API (DPAPI)
pub struct WindowsDpapiStorage {
    vault_path: PathBuf,
}

impl WindowsDpapiStorage {
    pub fn new(vault_path: PathBuf) -> Self {
        Self { vault_path }
    }

    /// Default vault location: `%LOCALAPPDATA%\CyberV\identity.vault`
    pub fn default_path() -> Result<Self, StorageError> {
        let local_appdata =
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let mut dir = PathBuf::from(local_appdata);
        dir.push("CyberV");
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        dir.push("identity.vault");
        Ok(Self::new(dir))
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let success = unsafe {
        CryptProtectData(
            &in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if success == 0 {
        return Err(StorageError::Dpapi(format!(
            "CryptProtectData failed with error code {}",
            std::io::Error::last_os_error()
        )));
    }

    let ciphertext = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        vec
    };

    Ok(ciphertext)
}

#[cfg(windows)]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let success = unsafe {
        CryptUnprotectData(
            &in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if success == 0 {
        return Err(StorageError::Dpapi(format!(
            "CryptUnprotectData failed with error code {}",
            std::io::Error::last_os_error()
        )));
    }

    let plaintext = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        vec
    };

    Ok(plaintext)
}

#[cfg(not(windows))]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    // Non-windows testing fallback: store plaintext with mock prefix
    let mut v = b"MOCK_PROTECT:".to_vec();
    v.extend_from_slice(plaintext);
    Ok(v)
}

#[cfg(not(windows))]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
    if !ciphertext.starts_with(b"MOCK_PROTECT:") {
        return Err(StorageError::Dpapi("Not a mock protected blob".into()));
    }
    Ok(ciphertext[13..].to_vec())
}

impl DeviceSecureStorage for WindowsDpapiStorage {
    fn load_identity(&self) -> Result<Option<PersistedIdentity>, StorageError> {
        if !self.vault_path.exists() {
            return Ok(None);
        }

        let encrypted_bytes = fs::read(&self.vault_path)?;
        let decrypted_vault = dpapi_unprotect(&encrypted_bytes)?;
        let identity = PersistedIdentity::from_vault_bytes(&decrypted_vault)?;
        Ok(Some(identity))
    }

    fn save_identity(&self, identity: &PersistedIdentity) -> Result<(), StorageError> {
        if let Some(parent) = self.vault_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let vault_bytes = identity.to_vault_bytes();
        let encrypted_bytes = dpapi_protect(&vault_bytes)?;

        // Write atomically via temporary file
        let tmp_path = self.vault_path.with_extension("tmp");
        fs::write(&tmp_path, encrypted_bytes)?;
        fs::rename(&tmp_path, &self.vault_path)?;
        Ok(())
    }

    fn clear_identity(&self) -> Result<(), StorageError> {
        if self.vault_path.exists() {
            fs::remove_file(&self.vault_path)?;
        }
        Ok(())
    }
}
