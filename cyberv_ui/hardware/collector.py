"""
Local Hardware Telemetry Collector for CyberV
Probes the actual physical hardware of the local machine using native Windows APIs & Registry.
Zero external dependencies, fast execution (< 30ms), fail-safe.
"""

import ctypes
import os
import platform
import sys
from typing import Any, Dict, List


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class LocalHardwareCollector:
    """Collects real hardware telemetry from the host machine."""

    @classmethod
    def get_cpu_info(cls) -> str:
        """Reads real CPU model string and core/thread count."""
        threads = os.cpu_count() or 1
        cpu_name = platform.processor() or "Unknown CPU"

        if sys.platform == "win32":
            try:
                import winreg

                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                ) as key:
                    raw_name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                    if raw_name:
                        cpu_name = raw_name.strip()
            except Exception:
                pass

        return f"{cpu_name} ({threads} Luồng Xử Lý)"

    @classmethod
    def get_motherboard_info(cls) -> str:
        """Reads motherboard manufacturer and product model from BIOS registry."""
        vendor = "Unknown Vendor"
        product = "Unknown Board"

        if sys.platform == "win32":
            try:
                import winreg

                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\BIOS",
                ) as key:
                    try:
                        vendor = winreg.QueryValueEx(key, "BaseBoardManufacturer")[0].strip()
                    except Exception:
                        pass
                    try:
                        product = winreg.QueryValueEx(key, "BaseBoardProduct")[0].strip()
                    except Exception:
                        pass
                    if not vendor or vendor == "System manufacturer":
                        try:
                            vendor = winreg.QueryValueEx(key, "SystemManufacturer")[0].strip()
                        except Exception:
                            pass
                    if not product or product == "System Product Name":
                        try:
                            product = winreg.QueryValueEx(key, "SystemProductName")[0].strip()
                        except Exception:
                            pass
            except Exception:
                pass

        return f"{vendor} ({product})"

    @classmethod
    def get_ram_info(cls) -> str:
        """Reads total physical memory capacity installed on the machine."""
        if sys.platform == "win32":
            try:
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    total_gb = stat.ullTotalPhys / (1024**3)
                    avail_gb = stat.ullAvailPhys / (1024**3)
                    return f"{total_gb:.1f} GB Physical Memory (Khả dụng: {avail_gb:.1f} GB)"
            except Exception:
                pass

        return "N/A (Chưa xác định dung lượng RAM)"

    @classmethod
    def get_gpu_info(cls) -> str:
        """Reads primary graphics adapter from Windows Video Driver Registry."""
        gpu_name = "Standard Display Adapter"

        if sys.platform == "win32":
            try:
                import winreg

                base_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as root_key:
                    for i in range(10):
                        sub_name = f"{i:04d}"
                        try:
                            with winreg.OpenKey(root_key, sub_name) as sub_key:
                                name, _ = winreg.QueryValueEx(sub_key, "DriverDesc")
                                if name and "Basic" not in name:
                                    gpu_name = name.strip()
                                    break
                                elif name:
                                    gpu_name = name.strip()
                        except Exception:
                            continue
            except Exception:
                pass

        return gpu_name

    @classmethod
    def get_storage_info(cls) -> str:
        """Reads system drive information and capacity."""
        sys_drive = os.getenv("SystemDrive", "C:")
        drive_letter = f"{sys_drive}\\"

        if sys.platform == "win32":
            try:
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                total_free_bytes = ctypes.c_ulonglong(0)
                if ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    drive_letter,
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    ctypes.byref(total_free_bytes),
                ):
                    total_gb = total_bytes.value / (1024**3)
                    free_gb = total_free_bytes.value / (1024**3)
                    return f"Ổ Đĩa Hệ Thống [{sys_drive}] - Tổng: {total_gb:.1f} GB (Trống: {free_gb:.1f} GB)"
            except Exception:
                pass

        return f"Ổ Đĩa Hệ Thống [{sys_drive}]"

    @classmethod
    def get_os_info(cls) -> str:
        """Reads Windows version and platform architecture."""
        try:
            return f"{platform.system()} {platform.release()} (Build {platform.version()}, {platform.machine()})"
        except Exception:
            return "Windows Operating System"

    @classmethod
    def get_tpm_evidence(cls) -> Dict[str, Any]:
        """Probes the physical TPM chip."""
        from .tpm_probe import TpmProbe
        return TpmProbe.probe_tpm()

    @classmethod
    def compute_local_fingerprint(cls) -> str:
        """
        Computes SHA-512 cryptographic hash over canonical local hardware observations.
        Docs/rvnew.md Section 9: This is strictly a Local Hardware Fingerprint (Unattested).
        """
        import hashlib
        canonical_str = (
            f"CPU:{cls.get_cpu_info()}|"
            f"MB:{cls.get_motherboard_info()}|"
            f"RAM:{cls.get_ram_info()}|"
            f"OS:{cls.get_os_info()}"
        )
        return hashlib.sha512(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def get_observed_hardware(cls) -> List[Dict[str, str]]:
        """
        Gathers complete real observed hardware specs for the SystemPage.
        Returns a list of dictionaries with 'component', 'model', and 'status'.
        Ref: Docs/rvnew.md Section 8: Status is strictly 'OBSERVED'.
        """
        tpm = cls.get_tpm_evidence()

        return [
            {
                "component": "1. Vi Xử Lý (CPU)",
                "model": cls.get_cpu_info(),
                "status": "OBSERVED",
            },
            {
                "component": "2. Bo Mạch Chủ (Mainboard)",
                "model": cls.get_motherboard_info(),
                "status": "OBSERVED",
            },
            {
                "component": "3. Bộ Nhớ RAM Vật Lý",
                "model": cls.get_ram_info(),
                "status": "OBSERVED",
            },
            {
                "component": "4. Card Đồ Họa (GPU)",
                "model": cls.get_gpu_info(),
                "status": "OBSERVED",
            },
            {
                "component": "5. Lưu Trữ Khởi Động (Storage)",
                "model": cls.get_storage_info(),
                "status": "OBSERVED",
            },
            {
                "component": "6. Môi Trường Hệ Điều Hành",
                "model": cls.get_os_info(),
                "status": "OBSERVED",
            },
            {
                "component": "7. Chip Bảo Mật TPM",
                "model": tpm.get("details", "Chưa xác định"),
                "status": tpm.get("status", "NOT_DETECTED"),
            },
        ]
