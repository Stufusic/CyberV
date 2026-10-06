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
#ifndef CYBERV_OB_CALLBACKS_H
#define CYBERV_OB_CALLBACKS_H

#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"

// Context struct for Object Manager Process Handle Filtering
typedef struct _CYBERV_PROTECTED_PROCESS_CONTEXT {
    ULONG ProcessId;
    ULONGLONG ProcessStartTime;
    CHAR RegistrationNonce[64];
    BOOLEAN IsActive;
    KSPIN_LOCK Lock;
} CYBERV_PROTECTED_PROCESS_CONTEXT, *PCYBERV_PROTECTED_PROCESS_CONTEXT;

// Initialize Object Manager Callbacks for process handle filtering
NTSTATUS InitializeObCallbacks(
    _Outptr_ PVOID *RegistrationHandle
);

// Unregister Object Manager Callbacks before driver unload
VOID UninitializeObCallbacks(
    _Inout_opt_ PVOID RegistrationHandle
);

// Register a target process to be protected from termination and memory tampering
NTSTATUS SetProtectedProcess(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartTime,
    _In_reads_bytes_(64) const char *Nonce
);

// Clear protected process state
VOID ClearProtectedProcess(VOID);

// Check if a given PID is currently registered as protected
BOOLEAN IsProcessProtected(
    _In_ HANDLE ProcessId
);

// Retrieve shield telemetry counters atomically
VOID GetShieldTelemetry(
    _Out_ PCYBERV_SHIELD_TELEMETRY Telemetry
);

// Pre-operation callback routine for process handle creation/duplication
OB_PREOP_CALLBACK_STATUS CyberVProcessPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

// Pre-operation callback routine for thread handle creation/duplication
// (blocks TerminateThread/SuspendThread/SetThreadContext against the
// protected agent's threads - a process-handle mask alone cannot block these)
OB_PREOP_CALLBACK_STATUS CyberVThreadPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

#endif // CYBERV_OB_CALLBACKS_H
