#ifndef CYBERV_IOCTL_H
#define CYBERV_IOCTL_H

// CyberV Probe KMDF Driver IOCTL Definitions
// Ref: Docs/rv10.md HCE-6 & Docs/rv11.md FSE-1
// Standardized ABI contract between Ring-0 Driver and Ring-3 Agent

#define FILE_DEVICE_CYBERV 0x8000
#define CYBERV_ABI_VERSION 1

// IOCTL Codes:
// IOCTL_CYBERV_GET_PCI_INFO:           0x80006000 (METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_CYBERV_GET_PCI_INFO \
    CTL_CODE(FILE_DEVICE_CYBERV, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

// IOCTL_CYBERV_GET_TOPOLOGY:           0x80006004 (METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_CYBERV_GET_TOPOLOGY \
    CTL_CODE(FILE_DEVICE_CYBERV, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

// IOCTL_CYBERV_REGISTER_PROTECTED_PID: 0x8000E008 (METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_CYBERV_REGISTER_PROTECTED_PID \
    CTL_CODE(FILE_DEVICE_CYBERV, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// IOCTL_CYBERV_GET_SHIELD_TELEMETRY:   0x8000600C (METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_CYBERV_GET_SHIELD_TELEMETRY \
    CTL_CODE(FILE_DEVICE_CYBERV, 0x803, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)

typedef struct _CYBERV_PCI_DEVICE {
    unsigned short VendorId;
    unsigned short DeviceId;
    unsigned short SubsystemVendorId;
    unsigned short SubsystemDeviceId;
    unsigned short Segment;
    unsigned char Bus;
    unsigned char Device;
    unsigned char Function;
    unsigned char DeviceClass;
    char SerialNumber[64];
} CYBERV_PCI_DEVICE, *PCYBERV_PCI_DEVICE;

typedef struct _CYBERV_KERNEL_OBSERVATION {
    unsigned int DriverVersion;
    unsigned int DeviceCount;
    unsigned long long ObservedAt;
    CYBERV_PCI_DEVICE Devices[32];
} CYBERV_KERNEL_OBSERVATION, *PCYBERV_KERNEL_OBSERVATION;

typedef struct _CYBERV_PROTECTED_PROCESS_REGISTRATION {
    unsigned int ProcessId;
    unsigned long long ProcessStartTime;
    char RegistrationNonce[64];
    unsigned int DriverInstanceId;
} CYBERV_PROTECTED_PROCESS_REGISTRATION, *PCYBERV_PROTECTED_PROCESS_REGISTRATION;

typedef struct _CYBERV_SHIELD_TELEMETRY {
    unsigned int ProtectedPid;
    unsigned int BlockedTerminations;
    unsigned int BlockedVmReads;
    unsigned int BlockedVmWrites;
    unsigned int SuspiciousAttempts;
    unsigned int DriverUnloadAttempts;
    unsigned int IsShieldActive;
} CYBERV_SHIELD_TELEMETRY, *PCYBERV_SHIELD_TELEMETRY;

#pragma pack(pop)

#endif // CYBERV_IOCTL_H
