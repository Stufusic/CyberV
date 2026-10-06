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
//! Cryptographic Random Number Generator Abstraction
//!
//! Ref: rv4.md #8:
//! "Thay SigningKey::generate(&mut OsRng) thành CryptoRngProvider / SecureRandom...
//! Production: Windows/OS CSPRNG. Test: Deterministic test RNG (chỉ cho phép trong test)."

use super::error::IdentityError;

/// Trait providing cryptographically secure random bytes
pub trait SecureRandom: Send + Sync {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), IdentityError>;
}

/// Production CSPRNG backed by the operating system kernel entropy pool
#[derive(Default)]
pub struct OsCryptoRng;

impl SecureRandom for OsCryptoRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), IdentityError> {
        getrandom::getrandom(dest).map_err(|e| IdentityError::RngFailure(e.to_string()))
    }
}
