// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
//! Kernel Tamper Resistance (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! Process registration integrity, ObCallbacks telemetry, Vault Shield, Degradation detection.

pub mod anti_tamper;
pub mod registration;
pub mod telemetry;
pub mod vault_shield;

pub use anti_tamper::{AntiTamperManager, AntiTamperReport, KERNEL_TAMPER_DERIVATION_VERSION};
pub use registration::ProtectedProcessRegistration;
pub use telemetry::{HandleOperationResult, ShieldTelemetry};
pub use vault_shield::{VaultShield, VaultShieldError};
