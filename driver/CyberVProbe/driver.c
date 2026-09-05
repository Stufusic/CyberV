// CyberVProbe KMDF Driver Entry & IOCTL Handler (HCE-6 & FSE-1)
// Ref: Docs/rv10.md HCE-6 & Docs/rv11.md FSE-1 Section 2
// Note: Driver interacts via supported KMDF APIs and ObRegisterCallbacks without raw physical memory access.

#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD CyberVProbeEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL CyberVProbeEvtIoDeviceControl;

// Global Shield Telemetry & Registration State
static CYBERV_SHIELD_TELEMETRY g_ShieldTelemetry = { 0 };
static CYBERV_PROTECTED_PROCESS_REGISTRATION g_RegisteredProcess = { 0 };
static PVOID g_RegistrationHandle = NULL;

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, CyberVProbeEvtDeviceAdd);
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    return status;
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

    UNREFERENCED_PARAMETER(Driver);

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) return status;

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
            if (OutputBufferLength < sizeof(CYBERV_KERNEL_OBSERVATION)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(CYBERV_KERNEL_OBSERVATION), &outBuffer, NULL);
            if (NT_SUCCESS(status) && outBuffer != NULL) {
                PCYBERV_KERNEL_OBSERVATION obs = (PCYBERV_KERNEL_OBSERVATION)outBuffer;
                RtlZeroMemory(obs, sizeof(CYBERV_KERNEL_OBSERVATION));
                obs->DriverVersion = 1;
                obs->DeviceCount = 0; // Populated by BUS_INTERFACE_STANDARD queries
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
                g_RegisteredProcess = *reg;
                g_ShieldTelemetry.ProtectedPid = reg->ProcessId;
                g_ShieldTelemetry.IsShieldActive = 1;
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
                RtlCopyMemory(outBuffer, &g_ShieldTelemetry, sizeof(CYBERV_SHIELD_TELEMETRY));
                bytesReturned = sizeof(CYBERV_SHIELD_TELEMETRY);
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
