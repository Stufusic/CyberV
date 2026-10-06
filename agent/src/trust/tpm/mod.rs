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
//! TPM 2.0 Subsystem Module (HCE-4)

pub mod capability;
pub mod detector;
pub mod errors;
pub mod key;
pub mod nv_counter;
pub mod pcr;
pub mod pcp;
pub mod provider;
pub mod tbs;
pub mod quote;

pub use capability::{TpmCapabilities, TpmStatus};
pub use detector::{MockTpmDetector, TpmDetector, WindowsTpmDetector};
pub use errors::TpmError;
pub use key::TpmIdentityKey;
pub use nv_counter::{
    MockTpmNvCounter, TpmAssuranceType, TpmNvAttributes, TpmNvCounter, TpmNvHandleInfo,
    WindowsTbsNvCounter, DEFAULT_CYBERV_NV_INDEX,
};
pub use pcr::{HashAlgorithm, PcrBank, PcrPolicy};
pub use pcp::{verify_p256, P256PublicKey, PcpAttestationKey, CYBERV_ATTEST_KEY_NAME};
pub use provider::{MockTpmProvider, TpmProvider};
pub use quote::{TpmAttestationPayload, TpmQuote};
