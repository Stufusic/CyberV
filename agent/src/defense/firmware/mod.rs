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
//! Firmware & Platform Integrity (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! Decoupled 4 domains: Secure Boot (with dbx precedence), Boot Guard / PSB,
//! SMM security (non-alarmist SMI), and Firmware Configuration.

pub mod boot_guard;
pub mod config;
pub mod fusion;
pub mod secure_boot;
pub mod smm;

pub use boot_guard::{BootGuardReport, HardwareBootTechnology};
pub use config::FirmwareConfigReport;
pub use fusion::{
    FirmwareEvidenceFusionEngine, FirmwareSecurityReport, FIRMWARE_DERIVATION_VERSION,
};
pub use secure_boot::{ImageValidationResult, SecureBootDbReport};
pub use smm::SmmSecurityReport;
