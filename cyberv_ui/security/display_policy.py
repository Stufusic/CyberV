"""
Security Display Policy & Gatekeeper (Invariants Enforcement)
Ref: Docs/ui.md Section 24 & Docs/rvnew.md Section 3, 4, 12, 13

Enforces the golden rules:
- Unknown != Protected
- Local != Protected (Zero Deceptive Signals: Local Assessment is NOT Kernel Protected)
- Anti-Downgrade Invariant: Protected -> Failed Service/Driver must become DEGRADED, NEVER LOCAL
- Never Fail-Open to Protected
- Widgets CANNOT override this policy!
"""

from typing import Optional
from ..models.protection import ProtectionState, ProtectionStateInfo


def resolve_display_state(
    kernel_available: bool,
    callback_active: bool,
    policy_decision: str,
    hardware_verified: bool = True,
    tpm_contradiction: bool = False,
    in_recovery: bool = False,
    is_ipc_connected: bool = True,
    session_was_protected: bool = False,
    is_verifying: bool = False,
    since_timestamp: str = "Just now",
    raw_reason: Optional[str] = None,
) -> ProtectionStateInfo:
    """
    Transforms raw backend agent telemetry into an invariant-enforced UI state.
    Guarantees no false security signal can ever reach the UI widgets.
    """
    norm_decision = (policy_decision or "").upper().strip()

    # Invariant Rule 0: Anti-Downgrade Invariant (Docs/rvnew.md Section 3 & 12)
    # If a session was once PROTECTED or had a verified service connection,
    # any failure of IPC or driver MUST drop to DEGRADED or ISOLATED.
    # It must NEVER downgrade back to a pleasant 'LOCAL' state!
    if session_was_protected and not is_ipc_connected:
        return ProtectionStateInfo(
            state=ProtectionState.DEGRADED,
            substate="IPC_DISCONNECTED",
            reason=raw_reason or "Mất kết nối với CyberV Core Agent Service",
            since=since_timestamp,
            confidence="LOW",
        )

    # Invariant Rule 1: Verifying / Handshaking (Docs/rvnew.md Section 13)
    if is_verifying:
        return ProtectionStateInfo(
            state=ProtectionState.VERIFYING,
            substate="SECURITY_HANDSHAKE",
            reason=raw_reason or "Đang bắt tay với CyberV Core và thẩm định lá chắn Kernel...",
            since=since_timestamp,
            confidence="MEDIUM",
        )

    # Invariant Rule 2: Local Assessment Mode (First run / Service absent)
    # Docs/rvnew.md Section 1: Truthful status, Kernel shield is INACTIVE.
    if not is_ipc_connected:
        return ProtectionStateInfo(
            state=ProtectionState.LOCAL,
            substate="LOCAL_ASSESSMENT",
            reason=(
                raw_reason
                or "Đang đánh giá phần cứng cục bộ. Kích hoạt dịch vụ để bật lá chắn Kernel 24/7."
            ),
            since=since_timestamp,
            confidence="MEDIUM",
        )

    # Invariant Rule 3: Emergency Lockdown (TPM Rollback or Policy Isolate)
    if tpm_contradiction or "ISOLATE" in norm_decision or "LOCKDOWN" in norm_decision:
        reason = "Emergency Security Isolation: Hardware rollback or policy violation detected"
        if raw_reason:
            reason = raw_reason
        elif tpm_contradiction:
            reason = "TPM NV Counter rollback contradiction detected"

        return ProtectionStateInfo(
            state=ProtectionState.ISOLATED,
            substate="EMERGENCY_LOCKDOWN",
            reason=reason,
            since=since_timestamp,
            confidence="HIGH",
        )

    # Invariant Rule 4: Recovery Pending
    if in_recovery or "RECOVERY" in norm_decision:
        return ProtectionStateInfo(
            state=ProtectionState.RECOVERY,
            substate="ADMIN_ATTESTATION_REQUIRED",
            reason=raw_reason or "Device awaiting cryptographic recovery attestation",
            since=since_timestamp,
            confidence="HIGH",
        )

    # Invariant Rule 5: Kernel Probe Offline or Callback Inactive
    if not kernel_available:
        return ProtectionStateInfo(
            state=ProtectionState.DEGRADED,
            substate="KERNEL_PROBE_OFFLINE",
            reason=raw_reason or "CyberV Kernel Driver is unavailable or not loaded",
            since=since_timestamp,
            confidence="HIGH",
        )

    if not callback_active:
        return ProtectionStateInfo(
            state=ProtectionState.DEGRADED,
            substate="CALLBACK_NOT_REGISTERED",
            reason=raw_reason or "Process Object Protection callback is not active",
            since=since_timestamp,
            confidence="HIGH",
        )

    # Invariant Rule 6: Hardware Evidence Not Verified
    if not hardware_verified:
        return ProtectionStateInfo(
            state=ProtectionState.DEGRADED,
            substate="EVIDENCE_UNVERIFIED",
            reason=raw_reason or "Hardware evidence topology has not been verified",
            since=since_timestamp,
            confidence="LOW",
        )

    # Invariant Rule 7: Normal Protected State (All invariant conditions met 100%)
    if norm_decision in ("ALLOW", "TRUSTED", "PROTECTED", "ACTIVE", "PROTECT"):
        return ProtectionStateInfo(
            state=ProtectionState.PROTECTED,
            substate="KERNEL_SHIELD_ACTIVE",
            reason="Kernel protection active and all invariant checks verified",
            since=since_timestamp,
            confidence="HIGH",
        )

    # Invariant Rule 8: Attention Required
    if "ATTENTION" in norm_decision or "MUTATION" in norm_decision:
        return ProtectionStateInfo(
            state=ProtectionState.ATTENTION,
            substate="HARDWARE_MUTATION_PENDING",
            reason=raw_reason or "Hardware topology change detected, pending review",
            since=since_timestamp,
            confidence="MEDIUM",
        )

    # Fallback to UNKNOWN
    return ProtectionStateInfo(
        state=ProtectionState.UNKNOWN,
        substate="UNVERIFIED_STATE",
        reason=raw_reason or f"Unknown backend security state: {policy_decision}",
        since=since_timestamp,
        confidence="LOW",
    )
