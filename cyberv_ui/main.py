"""
CyberV Desktop Native Security UI Entry Point
Ref: Docs/ui.md & Docs/ủiv.md
"""

import sys
import os
import argparse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberv_ui.app.application import CyberVApplication


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CyberV Endpoint Security - Desktop Native Client (PySide6)"
    )
    parser.add_argument(
        "--mock",
        type=str,
        default=None,
        choices=["protected", "degraded", "isolated", "recovery", "unknown", "driver_missing", "ipc_timeout"],
        help="Run UI with simulated security telemetry profile (offline development & QA)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Connect to live CyberVAgent Windows Service via Named Pipe IPC (default behavior)",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    is_live = (args.mock is None) or args.live

    print("================================================================================")
    print("  CyberV Endpoint Security - Desktop Native Client (PySide6)")
    print(f"  Execution Mode: {'MOCK PROFILE [' + args.mock.upper() + ']' if args.mock else 'LIVE NATIVE (Auto-Hardware Telemetry & Named Pipe IPC)'}")
    print("  UI Design System: Technical, Minimal, Trustworthy (Zero Deceptive Meters)")
    print("================================================================================")

    app = CyberVApplication(sys.argv, mock_profile=args.mock, live_mode=is_live)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
