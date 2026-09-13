"""
CyberV UI Design System - Color Palette & Theme Tokens
Ref: Docs/ui.md Section 4 & Docs/ủiv.md

Design Philosophy: Technical, Minimal, Trustworthy, Calm.
NO neon hacker, NO matrix rain, NO arbitrary decorative gauges.
"""

from dataclasses import dataclass
from PySide6.QtGui import QColor


@dataclass(frozen=True)
class StatusColorToken:
    primary: str        # Text / Main indicator
    bright: str         # Glowing dot / High contrast
    bg_subtle: str      # Background tint for badge / card
    border: str         # Border outline


class ThemePalette:
    # --------------------------------------------------------------------------
    # Base Neutrals (Dark Slate / Obsidian)
    # --------------------------------------------------------------------------
    BG_CANVAS = "#0D1117"          # Deep background
    BG_SURFACE = "#161B22"         # Card / container surface
    BG_SURFACE_HOVER = "#21262D"   # Hover state for cards
    BG_INPUT = "#0A0D12"           # Input / terminal background
    
    BORDER_DEFAULT = "#30363D"     # Standard division line
    BORDER_SUBTLE = "#21262D"      # Subtle separator
    BORDER_ACCENT = "#58A6FF"      # Focus ring
    
    TEXT_PRIMARY = "#E6EDF3"       # Main headers & body
    TEXT_SECONDARY = "#8B949E"     # Labels, subtitles
    TEXT_MUTED = "#6E7681"         # Placeholders, minor notes
    TEXT_INVERSE = "#0A0D12"       # Dark text on bright badge
    
    # --------------------------------------------------------------------------
    # Semantic Security Status Colors (Docs/ui.md Section 4.2)
    # --------------------------------------------------------------------------
    STATUS_PROTECTED = StatusColorToken(
        primary="#2EA043",
        bright="#3FB950",
        bg_subtle="#0D2A18",
        border="#1F6932",
    )
    
    STATUS_DEGRADED = StatusColorToken(
        primary="#D29922",
        bright="#F0B72F",
        bg_subtle="#2B2108",
        border="#6E4F0A",
    )
    
    STATUS_ATTENTION = StatusColorToken(
        primary="#DB6D28",
        bright="#F0883E",
        bg_subtle="#2A1608",
        border="#7A3911",
    )
    
    STATUS_ISOLATED = StatusColorToken(
        primary="#DA3633",
        bright="#F85149",
        bg_subtle="#2B0E10",
        border="#7A181C",
    )
    
    STATUS_UNKNOWN = StatusColorToken(
        primary="#8B949E",
        bright="#C9D1D9",
        bg_subtle="#1C2128",
        border="#373E47",
    )
    
    STATUS_LOCAL = StatusColorToken(
        primary="#58A6FF",
        bright="#79C0FF",
        bg_subtle="#0D2240",
        border="#1F6FEB",
    )

    STATUS_VERIFYING = StatusColorToken(
        primary="#D29922",
        bright="#F0B72F",
        bg_subtle="#2B2108",
        border="#6E4F0A",
    )
    
    STATUS_RECOVERY = StatusColorToken(
        primary="#8957E5",
        bright="#A371F7",
        bg_subtle="#1F1138",
        border="#4E2B8F",
    )

    @classmethod
    def get_status_token(cls, state_name: str) -> StatusColorToken:
        normalized = (state_name or "").upper().strip()
        mapping = {
            "LOCAL": cls.STATUS_LOCAL,
            "LOCAL ASSESSMENT": cls.STATUS_LOCAL,
            "LOCAL_ASSESSMENT": cls.STATUS_LOCAL,
            
            "PROTECTED": cls.STATUS_PROTECTED,
            "ACTIVE": cls.STATUS_PROTECTED,
            "RUNNING": cls.STATUS_PROTECTED,
            "PASS": cls.STATUS_PROTECTED,
            "VERIFIED": cls.STATUS_PROTECTED,
            "FRESH": cls.STATUS_PROTECTED,
            
            "DEGRADED": cls.STATUS_DEGRADED,
            "WARN": cls.STATUS_DEGRADED,
            "WARNING": cls.STATUS_DEGRADED,
            
            "ATTENTION": cls.STATUS_ATTENTION,
            "NOTICE": cls.STATUS_ATTENTION,
            
            "ISOLATED": cls.STATUS_ISOLATED,
            "FAIL": cls.STATUS_ISOLATED,
            "CRITICAL": cls.STATUS_ISOLATED,
            "ERROR": cls.STATUS_ISOLATED,
            "BLOCKED": cls.STATUS_ISOLATED,
            
            "RECOVERY": cls.STATUS_RECOVERY,
            "RECOVERYPENDING": cls.STATUS_RECOVERY,
            
            "STARTING": cls.STATUS_VERIFYING,
            "VERIFYING": cls.STATUS_VERIFYING,
            "HANDSHAKING": cls.STATUS_VERIFYING,
            
            "UNKNOWN": cls.STATUS_UNKNOWN,
            "OFFLINE": cls.STATUS_UNKNOWN,
            "NOT_INSTALLED": cls.STATUS_UNKNOWN,
        }
        return mapping.get(normalized, cls.STATUS_UNKNOWN)

    @classmethod
    def qcolor(cls, hex_code: str) -> QColor:
        return QColor(hex_code)
