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
//! CyberV Transport Error Types
//!
//! Ref: Rule.md Điều 18, 19: Phân định chi tiết lỗi mạng, không giấu lỗi.

use thiserror::Error;

/// Lỗi giao tiếp mạng giữa Agent và Cloud Edge Functions
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    #[error("Network connection failed: {0}")]
    NetworkFailure(String),

    #[error("Request timed out after deadline")]
    Timeout,

    #[error("Unauthorized (401): invalid or expired user JWT session")]
    Unauthorized,

    #[error("Forbidden (403): {0}")]
    Forbidden(String),

    #[error("Resource not found (404): {0}")]
    NotFound(String),

    #[error("Conflict (409): {0}")]
    Conflict(String),

    #[error("Server returned error ({0}): {1}")]
    ServerError(u16, String),

    #[error("Serialization or parsing error: {0}")]
    Serialization(String),
}
