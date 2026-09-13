"""
TPM 2.0 Security Hardware Probe for CyberV UI
Queries Windows WMI namespace 'Root\\CIMV2\\Security\\MicrosoftTpm' (Win32_Tpm).
Conforms to Docs/rvnew.md Section 10:
TPM presence is strictly an evidence observation ('DETECTED'), NEVER a full security verdict.
"""

import json
import subprocess
import sys
from typing import Any, Dict


class TpmProbe:
    """Probes the physical TPM (Trusted Platform Module) chip on Windows."""

    @classmethod
    def probe_tpm(cls) -> Dict[str, Any]:
        """
        Queries Win32_Tpm in Root\\CIMV2\\Security\\MicrosoftTpm.
        Returns detection metadata with strict 'DETECTED' or 'NOT_DETECTED' status.
        """
        default_result = {
            "is_present": False,
            "status": "NOT_DETECTED",
            "spec_version": "N/A",
            "is_enabled": False,
            "is_activated": False,
            "is_owned": False,
            "details": "Không phát hiện chip TPM hoặc quyền truy cập WMI bị giới hạn.",
        }

        if sys.platform != "win32":
            default_result["details"] = "Nền tảng không hỗ trợ Win32_Tpm."
            return default_result

        try:
            # Query Win32_Tpm using lightweight PowerShell CIM query
            cmd = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "Get-CimInstance -Namespace Root\\CIMV2\\Security\\MicrosoftTpm "
                    "-ClassName Win32_Tpm -ErrorAction SilentlyContinue | "
                    "Select-Object IsActivated_InitialValue, IsEnabled_InitialValue, "
                    "IsOwned_InitialValue, SpecVersion | ConvertTo-Json"
                ),
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                spec = str(data.get("SpecVersion", "2.0")).strip()
                is_enabled = bool(data.get("IsEnabled_InitialValue", False))
                is_activated = bool(data.get("IsActivated_InitialValue", False))
                is_owned = bool(data.get("IsOwned_InitialValue", False))

                return {
                    "is_present": True,
                    "status": "DETECTED",
                    "spec_version": spec,
                    "is_enabled": is_enabled,
                    "is_activated": is_activated,
                    "is_owned": is_owned,
                    "details": f"TPM {spec} (Enabled: {is_enabled}, Activated: {is_activated}, Owned: {is_owned})",
                }
        except Exception as e:
            default_result["details"] = f"Lỗi truy vấn TPM: {e}"

        return default_result
