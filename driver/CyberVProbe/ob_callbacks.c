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
// CyberV Probe KMDF Driver - Object Manager Callbacks (HCE-6 & FSE-1)
// Process AND thread handle filtering, kernel-side create-time capture,
// overwrite protection, telemetry counters.

#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"
#include "ob_callbacks.h"

// Manual import: create-time of a process as FILETIME (100ns since 1601).
// Client-supplied start times are only VERIFIED against this value, never trusted.
extern NTKERNELAPI LONGLONG PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS Process
);

static CYBERV_PROTECTED_PROCESS_CONTEXT g_ProtectedContext;
static CYBERV_SHIELD_TELEMETRY g_ShieldTelemetry;

// Access rights that must never be granted on handles to the protected agent:
// terminate, memory read/write, VM operation (VirtualAllocEx/VirtualProtectEx),
// duplicate handle, set information, suspend/resume, remote thread creation, quota.
static const ACCESS_MASK CyberV_DangerousProcessMask =
    PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
    PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME |
    PROCESS_CREATE_THREAD | PROCESS_SET_QUOTA;

// Thread-level rights that must never be granted on handles to the protected
// agent's threads: kill/wedge threads, hijack RIP, suspend, impersonate token.
static const ACCESS_MASK CyberV_DangerousThreadMask =
    THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT |
    THREAD_SET_INFORMATION | THREAD_IMPERSONATE | THREAD_SET_THREAD_TOKEN;

static OB_PREOP_CALLBACK_STATUS CyberVStripAccess(
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation,
    _In_ ACCESS_MASK DangerousMask
) {
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        ACCESS_MASK originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        ACCESS_MASK *desiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

        if (originalAccess & PROCESS_TERMINATE) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.BlockedTerminations);
        }
        if (originalAccess & PROCESS_VM_READ) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.BlockedVmReads);
        }
        if (originalAccess & PROCESS_VM_WRITE) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.BlockedVmWrites);
        }
        if (originalAccess & DangerousMask) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.SuspiciousAttempts);
        }

        *desiredAccess &= ~DangerousMask;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        ACCESS_MASK originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        ACCESS_MASK *desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        if (originalAccess & DangerousMask) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.SuspiciousAttempts);
        }

        *desiredAccess &= ~DangerousMask;
    }

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS CyberVProcessPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Never strip rights for kernel-internal handle operations
    if (OperationInformation->KernelHandle || ExGetPreviousMode() == KernelMode) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    // Capture the registered state while holding the lock, decide & strip below.
    // PsGetProcessCreateTimeQuadPart is called BEFORE taking the lock (target
    // PEPROCESS is already referenced by the object manager) to keep the
    // critical section minimal.
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    BOOLEAN isTarget = g_ProtectedContext.IsActive &&
                       (ULONG)(ULONG_PTR)targetPid == g_ProtectedContext.ProcessId;
    ULONGLONG registeredStartTime = g_ProtectedContext.ProcessStartTime;

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (!isTarget) {
        return OB_PREOP_SUCCESS;
    }

    // Anti-PID Reuse Enforcement: the registered create time is captured
    // KERNEL-SIDE at registration (PsGetProcessCreateTimeQuadPart, FILETIME
    // 100ns since 1601). A recycled PID belongs to a process with a different
    // create time -> it is NOT the agent, do not protect the foreign process.
    if (registeredStartTime != 0) {
        LONGLONG currentCreateTime = PsGetProcessCreateTimeQuadPart(targetProcess);
        if ((ULONGLONG)currentCreateTime != registeredStartTime) {
            return OB_PREOP_SUCCESS;
        }
    }

    // Target is the protected CyberV Agent process!
    return CyberVStripAccess(OperationInformation, CyberV_DangerousProcessMask);
}

OB_PREOP_CALLBACK_STATUS CyberVThreadPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Never strip rights for kernel-internal handle operations
    if (OperationInformation->KernelHandle || ExGetPreviousMode() == KernelMode) {
        return OB_PREOP_SUCCESS;
    }

    PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
    HANDLE threadProcessPid = PsGetThreadProcessId(targetThread);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    BOOLEAN isTarget = g_ProtectedContext.IsActive &&
                       (ULONG)(ULONG_PTR)threadProcessPid == g_ProtectedContext.ProcessId;

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (!isTarget) {
        return OB_PREOP_SUCCESS;
    }

    // Threads of the protected agent: strip terminate/suspend/SetThreadContext/
    // impersonation rights that the process-handle mask alone cannot block.
    return CyberVStripAccess(OperationInformation, CyberV_DangerousThreadMask);
}

// Registration arrays must be resident; file-scope static guarantees non-paged.
static OB_OPERATION_REGISTRATION g_OpRegistrations[2];

NTSTATUS InitializeObCallbacks(
    _Outptr_ PVOID *RegistrationHandle
) {
    if (RegistrationHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeSpinLock(&g_ProtectedContext.Lock);
    *RegistrationHandle = NULL;

    // Operation 1: process handles (terminate / VM tampering / dup handle...)
    RtlZeroMemory(g_OpRegistrations, sizeof(g_OpRegistrations));
    g_OpRegistrations[0].ObjectType = PsProcessType;
    g_OpRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpRegistrations[0].PreOperation = CyberVProcessPreOperationCallback;
    g_OpRegistrations[0].PostOperation = NULL;

    // Operation 2: thread handles of the protected process (TerminateThread /
    // SuspendThread / SetThreadContext bypass the process-handle mask entirely)
    g_OpRegistrations[1].ObjectType = PsThreadType;
    g_OpRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpRegistrations[1].PreOperation = CyberVThreadPreOperationCallback;
    g_OpRegistrations[1].PostOperation = NULL;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"385201"); // CyberV Security Altitude

    OB_CALLBACK_REGISTRATION cbReg;
    RtlZeroMemory(&cbReg, sizeof(OB_CALLBACK_REGISTRATION));
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 2;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = g_OpRegistrations;

    NTSTATUS status = ObRegisterCallbacks(&cbReg, RegistrationHandle);
    if (!NT_SUCCESS(status)) {
        *RegistrationHandle = NULL;
        return status;
    }

    g_ShieldTelemetry.IsShieldActive = 1;
    return STATUS_SUCCESS;
}

VOID UninitializeObCallbacks(
    _Inout_opt_ PVOID RegistrationHandle
) {
    ClearProtectedProcess();

    if (RegistrationHandle != NULL) {
        ObUnRegisterCallbacks(RegistrationHandle);
    }

    g_ShieldTelemetry.IsShieldActive = 0;
}

NTSTATUS SetProtectedProcess(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartTime,
    _In_reads_bytes_(64) const char *Nonce
) {
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Kernel-side create-time capture: NEVER trust the client-supplied value.
    // The user-mode "seconds since 1970" register request historically
    // mismatched the kernel FILETIME (100ns since 1601) unit/epoch, silently
    // disabling the PID-reuse check. We now look the true value up ourselves
    // and only VERIFY the client's advisory value when non-zero.
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
    if (!NT_SUCCESS(status) || targetProcess == NULL) {
        return STATUS_INVALID_PARAMETER; // Process does not exist (yet) -> refuse to register
    }

    ULONGLONG trueCreateTime = (ULONGLONG)PsGetProcessCreateTimeQuadPart(targetProcess);
    ObDereferenceObject(targetProcess);

    if (ProcessStartTime != 0 && ProcessStartTime != trueCreateTime) {
        // Client claims a create time that does not match the kernel record:
        // either a stale client or an attempted registration for a recycled PID.
        return STATUS_REVISION_MISMATCH;
    }

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    // Overwrite protection: an active registration for a DIFFERENT process
    // must not be silently replaced (that would unregister the agent's
    // protection without any trace). Re-registration of the same process
    // (same PID + same kernel-captured create time) is idempotent.
    if (g_ProtectedContext.IsActive &&
        g_ProtectedContext.ProcessId != ProcessId &&
        g_ProtectedContext.ProcessStartTime != trueCreateTime) {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_DEVICE_BUSY; // Existing protection must be cleared explicitly first
    }

    g_ProtectedContext.ProcessId = ProcessId;
    g_ProtectedContext.ProcessStartTime = trueCreateTime; // kernel-captured, not client-supplied
    if (Nonce != NULL) {
        RtlCopyMemory(g_ProtectedContext.RegistrationNonce, Nonce, 64);
    }
    g_ProtectedContext.IsActive = TRUE;

    g_ShieldTelemetry.ProtectedPid = ProcessId;
    g_ShieldTelemetry.IsShieldActive = 1;

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_SUCCESS;
}

VOID ClearProtectedProcess(VOID) {
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    g_ProtectedContext.ProcessId = 0;
    g_ProtectedContext.ProcessStartTime = 0;
    RtlZeroMemory(g_ProtectedContext.RegistrationNonce, sizeof(g_ProtectedContext.RegistrationNonce));
    g_ProtectedContext.IsActive = FALSE;

    g_ShieldTelemetry.ProtectedPid = 0;

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

BOOLEAN IsProcessProtected(
    _In_ HANDLE ProcessId
) {
    BOOLEAN isProtected = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    if (g_ProtectedContext.IsActive && (ULONG)(ULONG_PTR)ProcessId == g_ProtectedContext.ProcessId) {
        isProtected = TRUE;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return isProtected;
}

VOID GetShieldTelemetry(
    _Out_ PCYBERV_SHIELD_TELEMETRY Telemetry
) {
    if (Telemetry != NULL) {
        RtlCopyMemory(Telemetry, &g_ShieldTelemetry, sizeof(CYBERV_SHIELD_TELEMETRY));
    }
}
