// CyberVProbe Object Manager Callback Implementation (HCE-6 & FSE-1)
// Enforces Ring-0 handle filtering to prevent process termination, memory scraping, and injection.

#include "ob_callbacks.h"

// Global Protected Process Context
static CYBERV_PROTECTED_PROCESS_CONTEXT g_ProtectedContext = { 0 };
static CYBERV_SHIELD_TELEMETRY g_ShieldTelemetry = { 0 };

extern LONGLONG PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);

OB_PREOP_CALLBACK_STATUS CyberVProcessPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only process operations on process objects
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    // Never restrict kernel-mode operations
    if (OperationInformation->KernelHandle == 1 || ExGetPreviousMode() == KernelMode) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    if (!g_ProtectedContext.IsActive || (ULONG)(ULONG_PTR)targetPid != g_ProtectedContext.ProcessId) {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return OB_PREOP_SUCCESS;
    }

    // Anti-PID Reuse Enforcement: Verify process creation time matches registered process
    if (g_ProtectedContext.ProcessStartTime != 0) {
        LONGLONG currentCreateTime = PsGetProcessCreateTimeQuadPart(targetProcess);
        if ((ULONGLONG)currentCreateTime != g_ProtectedContext.ProcessStartTime) {
            // OS recycled the PID for another process -> do not protect foreign process!
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            return OB_PREOP_SUCCESS;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // Target is the protected CyberV Agent process!
    // Strip dangerous access masks to defend against termination, VM reading/writing, and thread injection
    ACCESS_MASK dangerousMask = PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE |
                               PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME;

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
        if (originalAccess & dangerousMask) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.SuspiciousAttempts);
        }

        // Strip the rights
        *desiredAccess &= ~dangerousMask;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        ACCESS_MASK originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        ACCESS_MASK *desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        if (originalAccess & dangerousMask) {
            InterlockedIncrement((LONG*)&g_ShieldTelemetry.SuspiciousAttempts);
        }

        *desiredAccess &= ~dangerousMask;
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS InitializeObCallbacks(
    _Outptr_ PVOID *RegistrationHandle
) {
    if (RegistrationHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeSpinLock(&g_ProtectedContext.Lock);
    *RegistrationHandle = NULL;

    OB_OPERATION_REGISTRATION opReg;
    RtlZeroMemory(&opReg, sizeof(OB_OPERATION_REGISTRATION));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = CyberVProcessPreOperationCallback;
    opReg.PostOperation = NULL;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"385201"); // CyberV Security Altitude

    OB_CALLBACK_REGISTRATION cbReg;
    RtlZeroMemory(&cbReg, sizeof(OB_CALLBACK_REGISTRATION));
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

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

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedContext.Lock, &lockHandle);

    g_ProtectedContext.ProcessId = ProcessId;
    g_ProtectedContext.ProcessStartTime = ProcessStartTime;
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
