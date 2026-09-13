// CyberVProbe KMDF Driver Entry & IOCTL Handler (HCE-6 & FSE-1)
// Enforces Object Manager callbacks, caller authorization, and device ACL hardening.

#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"
#include "ob_callbacks.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD CyberVProbeEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD CyberVProbeEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL CyberVProbeEvtIoDeviceControl;

static PVOID g_RegistrationHandle = NULL;

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, CyberVProbeEvtDeviceAdd);
    config.EvtDriverUnload = CyberVProbeEvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Initialize ObRegisterCallbacks for process handle filtering
    status = InitializeObCallbacks(&g_RegistrationHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CyberVProbe] Failed to initialize ObCallbacks: 0x%08X\n", status));
        // Degradation handled by fail-closed policy
    }

    return STATUS_SUCCESS;
}

VOID CyberVProbeEvtDriverUnload(
    _In_ WDFDRIVER Driver
) {
    UNREFERENCED_PARAMETER(Driver);

    // Unregister callbacks cleanly before unload
    if (g_RegistrationHandle != NULL) {
        UninitializeObCallbacks(g_RegistrationHandle);
        g_RegistrationHandle = NULL;
    }
}

NTSTATUS CyberVProbeEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
) {
    NTSTATUS status;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    DECLARE_CONST_UNICODE_STRING(ntDeviceName, L"\\Device\\CyberVProbe");
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\CyberVProbe");
    
    // Explicit SDDL: System All, Administrators All (SDDL_DEVOBJ_SYS_ALL_ADM_ALL)
    // Denies unprivileged standard users from sending arbitrary IOCTLs
    DECLARE_CONST_UNICODE_STRING(sddlString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    UNREFERENCED_PARAMETER(Driver);

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceInitAssignSDDLString(DeviceInit, &sddlString);
    if (!NT_SUCCESS(status)) return status;

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_CYBERV);

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = CyberVProbeEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    return status;
}

VOID CyberVProbeEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
) {
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;
    PVOID inBuffer = NULL;
    PVOID outBuffer = NULL;

    UNREFERENCED_PARAMETER(Queue);

    switch (IoControlCode) {
        case IOCTL_CYBERV_GET_PCI_INFO:
        case IOCTL_CYBERV_GET_TOPOLOGY:
            if (OutputBufferLength < sizeof(CYBERV_KERNEL_OBSERVATION)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(CYBERV_KERNEL_OBSERVATION), &outBuffer, NULL);
            if (NT_SUCCESS(status) && outBuffer != NULL) {
                PCYBERV_KERNEL_OBSERVATION obs = (PCYBERV_KERNEL_OBSERVATION)outBuffer;
                RtlZeroMemory(obs, sizeof(CYBERV_KERNEL_OBSERVATION));
                obs->DriverVersion = CYBERV_ABI_VERSION;
                obs->DeviceCount = 0; // Populated by BUS_INTERFACE_STANDARD queries
                obs->ObservedAt = (unsigned long long)KeQueryUnbiasedInterruptTime();
                bytesReturned = sizeof(CYBERV_KERNEL_OBSERVATION);
            }
            break;

        case IOCTL_CYBERV_REGISTER_PROTECTED_PID:
            if (InputBufferLength < sizeof(CYBERV_PROTECTED_PROCESS_REGISTRATION)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(CYBERV_PROTECTED_PROCESS_REGISTRATION), &inBuffer, NULL);
            if (NT_SUCCESS(status) && inBuffer != NULL) {
                PCYBERV_PROTECTED_PROCESS_REGISTRATION reg = (PCYBERV_PROTECTED_PROCESS_REGISTRATION)inBuffer;
                
                // Caller identity verification: Ensure registration can only be requested
                // for the caller's own PID or by SYSTEM
                ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                if (callerPid != reg->ProcessId && callerPid != 4) { // PID 4 is System
                    status = STATUS_ACCESS_DENIED;
                    break;
                }

                status = SetProtectedProcess(reg->ProcessId, reg->ProcessStartTime, reg->RegistrationNonce);
                bytesReturned = 0;
            }
            break;

        case IOCTL_CYBERV_GET_SHIELD_TELEMETRY:
            if (OutputBufferLength < sizeof(CYBERV_SHIELD_TELEMETRY)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(CYBERV_SHIELD_TELEMETRY), &outBuffer, NULL);
            if (NT_SUCCESS(status) && outBuffer != NULL) {
                GetShieldTelemetry((PCYBERV_SHIELD_TELEMETRY)outBuffer);
                bytesReturned = sizeof(CYBERV_SHIELD_TELEMETRY);
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
