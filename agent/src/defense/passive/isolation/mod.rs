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
//! Dual-Process Broker - Worker Privilege Separation & Sandbox (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 4, 5, 6, 10:
//! - Core Broker: SYSTEM, Vault, TPM, Driver, Local Policy. Zero-Network.
//! - Network Worker: AppContainer Sandbox, Supabase, Dashboard IPC.
//! - Multi-Layer Hardened IPC: Named Pipe DACL + SID Auth + Ephemeral Crypto + Monotonic Seq + Bounds.
//! - Broker Policy Admission Controller: Zero-Trust verification of policy submissions.

pub mod admission;
pub mod broker;
pub mod protocol;
pub mod worker;

pub use admission::{
    decode_hex, encode_hex, BrokerPolicyAdmissionController, PolicyAdmissionError,
    SignedPolicyEnvelope, DOMAIN_POLICY_ADMISSION,
};

pub use broker::{BrokerError, BrokerStatus, CoreBroker, EXPECTED_WORKER_APPCONTAINER_SID};
pub use protocol::{
    compute_frame_mac, generate_session_key, BrokerRpcCommand, IpcFrameError, RpcEnvelope,
    RpcSessionValidator, CURRENT_IPC_PROTOCOL_VERSION, DOMAIN_BROKER_FRAME_MAC,
    MAX_IPC_FRAME_SIZE,
};
pub use worker::{NetworkWorkerDaemon, WorkerSandboxProfile};
