// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! Secure Boot Database & DBX Revocation Precedence (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! "Secure Boot PK, KEK, db, dbx thực sự là những database có vai trò khác nhau;
//! dbx là danh sách revoked và có precedence (ưu tiên tối cao) khi một image xuất hiện ở cả db và dbx."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageValidationResult {
    AllowedByDb,
    RevokedByDbxPrecedence,
    UntrustedNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootDbReport {
    pub is_secure_boot_enabled: bool,
    pub pk_present: bool,
    pub kek_count: u32,
    pub db_count: u32,
    pub dbx_count: u32,
}

impl SecureBootDbReport {
    pub fn standard_hardened() -> Self {
        Self {
            is_secure_boot_enabled: true,
            pk_present: true,
            kek_count: 2,
            db_count: 5,
            dbx_count: 382, // Standard Windows UEFI revocation list count
        }
    }

    pub fn unconfigured() -> Self {
        Self {
            is_secure_boot_enabled: false,
            pk_present: false,
            kek_count: 0,
            db_count: 0,
            dbx_count: 0,
        }
    }

    /// Kiểm tra tính hợp lệ của image dựa trên nguyên tắc ưu tiên tối cao của DBX
    pub fn validate_image_precedence(&self, in_db: bool, in_dbx: bool) -> ImageValidationResult {
        if in_dbx {
            // DBX luôn có precedence cao hơn DB
            ImageValidationResult::RevokedByDbxPrecedence
        } else if in_db && self.is_secure_boot_enabled {
            ImageValidationResult::AllowedByDb
        } else {
            ImageValidationResult::UntrustedNotFound
        }
    }

    pub fn security_score(&self) -> u32 {
        if !self.is_secure_boot_enabled {
            return 1000;
        }

        let mut score = 5000; // Base for enabled
        if self.pk_present {
            score += 2000;
        }
        if self.kek_count > 0 {
            score += 1000;
        }
        if self.db_count > 0 {
            score += 1000;
        }
        if self.dbx_count >= 100 {
            score += 1000;
        } // Có danh sách thu hồi đầy đủ

        score.min(10000)
    }
}
