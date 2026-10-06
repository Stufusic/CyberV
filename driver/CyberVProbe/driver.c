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
// CyberVProbe KMDF Driver Entry & IOCTL Handler (HCE-6 & FSE-1)
// Enforces Object Manager callbacks, caller authorization, and device ACL hardening.

#include <ntddk.h>
#include <wdf.h>
#include <ntddstor.h>
#include <ntstrsafe.h>
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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[CyberVProbe] CRITICAL: Failed to initialize ObCallbacks: 0x%08X - Aborting driver load (Fail-Closed)\n", status));
        return status;
    }

    return STATUS_SUCCESS;
}

static VOID CyberVQueryStorageSerial(
    _In_ ULONG diskIndex,
    _Out_writes_bytes_(maxLen) PCHAR outSerial,
    _In_ ULONG maxLen
) {
    if (outSerial == NULL || maxLen == 0) return;
    RtlZeroMemory(outSerial, maxLen);

    UNICODE_STRING deviceName;
    WCHAR deviceNameBuf[64];
    NTSTATUS status = RtlStringCchPrintfW(deviceNameBuf, 64, L"\\Device\\Harddisk%lu\\DR%lu", diskIndex, diskIndex);
    if (!NT_SUCCESS(status)) return;
    RtlInitUnicodeString(&deviceName, deviceNameBuf);

    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject);
    if (!NT_SUCCESS(status) || fileObject == NULL || deviceObject == NULL) {
        return;
    }

    STORAGE_PROPERTY_QUERY query;
    RtlZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    UCHAR buffer[512];
    RtlZeroMemory(buffer, sizeof(buffer));

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IO_STATUS_BLOCK ioStatus;

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_QUERY_PROPERTY,
        deviceObject,
        &query,
        sizeof(query),
        buffer,
        sizeof(buffer),
        FALSE,
        &event,
        &ioStatus
    );

    if (irp != NULL) {
        status = IoCallDriver(deviceObject, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = ioStatus.Status;
        }

        if (NT_SUCCESS(status) && ioStatus.Information >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)buffer;
            // Variable storage descriptor bounds check
            if (desc->SerialNumberOffset != 0 && desc->SerialNumberOffset < ioStatus.Information) {
                PCSTR serial = (PCSTR)(buffer + desc->SerialNumberOffset);
                ULONG serialLen = 0;
                while (desc->SerialNumberOffset + serialLen < ioStatus.Information && serial[serialLen] != '\0' && serialLen < maxLen - 1) {
                    outSerial[serialLen] = serial[serialLen];
                    serialLen++;
                }
                outSerial[serialLen] = '\0';
            }
        }
    }

    ObDereferenceObject(fileObject);
}

static VOID CyberVCollectPciTopology(_Out_ PCYBERV_KERNEL_OBSERVATION obs) {
    UNICODE_STRING pciRegPath;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hPciKey = NULL;
    NTSTATUS status;

    obs->DeviceCount = 0;

    RtlInitUnicodeString(&pciRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI");
    InitializeObjectAttributes(&objAttr, &pciRegPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hPciKey, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status) || hPciKey == NULL) {
        return;
    }

    UCHAR buffer[512];
    PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)buffer;
    ULONG resultLength = 0;
    ULONG index = 0;

    while (obs->DeviceCount < 32) {
        status = ZwEnumerateKey(hPciKey, index, KeyBasicInformation, keyInfo, sizeof(buffer), &resultLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (keyInfo->NameLength >= 17 * sizeof(WCHAR)) {
            PWCHAR name = keyInfo->Name;
            ULONG nameChars = keyInfo->NameLength / sizeof(WCHAR);
            ULONG ven = 0;
            ULONG dev = 0;
            BOOLEAN foundVen = FALSE;
            BOOLEAN foundDev = FALSE;

            for (ULONG i = 0; i + 8 <= nameChars; i++) {
                if (!foundVen && name[i] == L'V' && name[i+1] == L'E' && name[i+2] == L'N' && name[i+3] == L'_') {
                    for (ULONG h = 0; h < 4; h++) {
                        WCHAR c = name[i + 4 + h];
                        ULONG val = 0;
                        if (c >= L'0' && c <= L'9') val = c - L'0';
                        else if (c >= L'A' && c <= L'F') val = c - L'A' + 10;
                        else if (c >= L'a' && c <= L'f') val = c - L'a' + 10;
                        ven = (ven << 4) | val;
                    }
                    foundVen = TRUE;
                }
                if (!foundDev && name[i] == L'D' && name[i+1] == L'E' && name[i+2] == L'V' && name[i+3] == L'_') {
                    for (ULONG h = 0; h < 4; h++) {
                        WCHAR c = name[i + 4 + h];
                        ULONG val = 0;
                        if (c >= L'0' && c <= L'9') val = c - L'0';
                        else if (c >= L'A' && c <= L'F') val = c - L'A' + 10;
                        else if (c >= L'a' && c <= L'f') val = c - L'a' + 10;
                        dev = (dev << 4) | val;
                    }
                    foundDev = TRUE;
                }
            }

            // Header Type check: Type 0 endpoint vs Type 1/2 bridge
            BOOLEAN isBridge = FALSE;
            UCHAR deviceClass = 0x01; // Default Type 0 endpoint (Mass Storage)
            for (ULONG i = 0; i + 5 <= nameChars; i++) {
                if (name[i] == L'C' && name[i+1] == L'C' && name[i+2] == L'_') {
                    if (name[i+3] == L'0' && name[i+4] == L'6') {
                        isBridge = TRUE; // Header Type 1/2 Bridge
                        deviceClass = 0x06;
                    } else if (name[i+3] == L'0' && name[i+4] == L'1') {
                        deviceClass = 0x01; // Mass Storage
                    } else if (name[i+3] == L'0' && name[i+4] == L'2') {
                        deviceClass = 0x02; // Network
                    } else if (name[i+3] == L'0' && name[i+4] == L'3') {
                        deviceClass = 0x03; // Display
                    }
                    break;
                }
            }

            if (foundVen && foundDev && ven != 0 && dev != 0) {
                obs->Devices[obs->DeviceCount].VendorId = (unsigned short)ven;
                obs->Devices[obs->DeviceCount].DeviceId = (unsigned short)dev;
                obs->Devices[obs->DeviceCount].SubsystemVendorId = (unsigned short)ven;
                obs->Devices[obs->DeviceCount].SubsystemDeviceId = (unsigned short)dev;
                obs->Devices[obs->DeviceCount].Segment = 0;
                obs->Devices[obs->DeviceCount].Bus = (unsigned char)(index & 0xFF);
                obs->Devices[obs->DeviceCount].Device = (unsigned char)((index >> 3) & 0x1F);
                obs->Devices[obs->DeviceCount].Function = (unsigned char)(index & 0x07);
                obs->Devices[obs->DeviceCount].DeviceClass = deviceClass;

                // Nếu là Mass Storage (Header Type 0 endpoint), truy vấn serial đĩa qua IOCTL_STORAGE_QUERY_PROPERTY
                if (!isBridge && deviceClass == 0x01) {
                    CyberVQueryStorageSerial(
                        obs->DeviceCount,
                        obs->Devices[obs->DeviceCount].SerialNumber,
                        sizeof(obs->Devices[obs->DeviceCount].SerialNumber)
                    );
                }

                obs->DeviceCount++;
            }
        }

        index++;
    }

    ZwClose(hPciKey);
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
                obs->ObservedAt = (unsigned long long)KeQueryUnbiasedInterruptTime();
                CyberVCollectPciTopology(obs);
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

                // ABI anti-drift: reject clients built against a different ABI version
                if (reg->ClientAbiVersion != CYBERV_ABI_VERSION) {
                    status = STATUS_REVISION_MISMATCH;
                    break;
                }

                // Caller identity verification: registration is only allowed for
                // the caller's OWN PID. The former "PID 4 = System" bypass also
                // admitted any kernel-thread-originated (Zw*) request and has no
                // legitimate use: the CyberVAgent service runs in its own process.
                // NOTE: this IOCTL completes inline (never pended), so the current
                // thread still belongs to the requesting process.
                ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                if (callerPid != reg->ProcessId) {
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
