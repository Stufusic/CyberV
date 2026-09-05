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
    SignedPolicyEnvelope,
};

pub use broker::{BrokerError, BrokerStatus, CoreBroker, EXPECTED_WORKER_APPCONTAINER_SID};
pub use protocol::{
    BrokerRpcCommand, IpcFrameError, RpcEnvelope, RpcSessionValidator,
    CURRENT_IPC_PROTOCOL_VERSION, MAX_IPC_FRAME_SIZE,
};
pub use worker::{NetworkWorkerDaemon, WorkerSandboxProfile};
