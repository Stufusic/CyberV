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
//! CyberV Device Cryptographic Identity Subsystem
//!
//! Manages stable Ed25519 device keypairs, secret encapsulation without leaky serialization,
//! secure random number generation, OS-protected identity persistence, and HKDF state-bound derivation.
//!
//! Ref: rv4.md: "Identity Sống Lâu — State Sống Ngắn".

pub mod error;
pub mod kdf;
pub mod keypair;
pub mod rng;
pub mod secret;
pub mod storage;

pub use error::IdentityError;
pub use kdf::{derive_state_bound_bytes, derive_state_bound_material};
pub use keypair::DeviceIdentityKey;
pub use rng::{OsCryptoRng, SecureRandom};
pub use secret::Secret32;
pub use storage::{
    DeviceSecureStorage, MockSecureStorage, PersistedIdentity, StorageError, WindowsDpapiStorage,
};
