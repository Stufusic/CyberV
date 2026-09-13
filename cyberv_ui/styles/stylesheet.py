"""
CyberV UI - Global Qt StyleSheet (QSS)
Ref: Docs/ui.md Section 4

Clean, technical, responsive stylesheet for PySide6.
"""

from .palette import ThemePalette


def get_application_stylesheet() -> str:
    p = ThemePalette
    return f"""
    /* ========================================================================= */
    /* Global Application Styles                                                 */
    /* ========================================================================= */
    QMainWindow, QDialog, QWidget#central_widget {{
        background-color: {p.BG_CANVAS};
        color: {p.TEXT_PRIMARY};
        font-family: "Segoe UI", "Inter", -apple-system, sans-serif;
        font-size: 13px;
    }}

    /* ========================================================================= */
    /* Typography & Headers                                                      */
    /* ========================================================================= */
    QLabel {{
        color: {p.TEXT_PRIMARY};
        background: transparent;
    }}

    QLabel#page_title {{
        font-size: 20px;
        font-weight: 700;
        color: {p.TEXT_PRIMARY};
        padding: 4px 0px;
    }}

    QLabel#page_subtitle {{
        font-size: 12px;
        color: {p.TEXT_SECONDARY};
    }}

    QLabel#section_header {{
        font-size: 14px;
        font-weight: 600;
        color: {p.TEXT_PRIMARY};
        letter-spacing: 0.5px;
    }}

    QLabel#mono_text {{
        font-family: "Consolas", "JetBrains Mono", "Cascadia Code", monospace;
        font-size: 12px;
        color: {p.TEXT_PRIMARY};
    }}

    /* ========================================================================= */
    /* Containers & Cards                                                        */
    /* ========================================================================= */
    QFrame#card {{
        background-color: {p.BG_SURFACE};
        border: 1px solid {p.BORDER_DEFAULT};
        border-radius: 8px;
        padding: 16px;
    }}

    QFrame#card:hover {{
        border: 1px solid {p.BORDER_ACCENT};
    }}

    QFrame#sidebar {{
        background-color: {p.BG_SURFACE};
        border-right: 1px solid {p.BORDER_DEFAULT};
    }}

    QFrame#top_bar {{
        background-color: {p.BG_SURFACE};
        border-bottom: 1px solid {p.BORDER_DEFAULT};
        padding: 8px 16px;
    }}

    /* ========================================================================= */
    /* Push Buttons                                                              */
    /* ========================================================================= */
    QPushButton {{
        background-color: {p.BG_SURFACE_HOVER};
        color: {p.TEXT_PRIMARY};
        border: 1px solid {p.BORDER_DEFAULT};
        border-radius: 6px;
        padding: 7px 16px;
        font-weight: 500;
        font-size: 12px;
    }}

    QPushButton:hover {{
        background-color: #2D333B;
        border: 1px solid {p.TEXT_MUTED};
    }}

    QPushButton:pressed {{
        background-color: {p.BG_CANVAS};
        border: 1px solid {p.BORDER_DEFAULT};
    }}

    QPushButton:disabled {{
        background-color: {p.BG_INPUT};
        color: {p.TEXT_MUTED};
        border: 1px solid {p.BORDER_SUBTLE};
    }}

    QPushButton#primary_btn {{
        background-color: #1F6FEB;
        color: #FFFFFF;
        border: 1px solid #388BFD;
        font-weight: 600;
    }}

    QPushButton#primary_btn:hover {{
        background-color: #388BFD;
    }}

    QPushButton#danger_btn {{
        background-color: {p.STATUS_ISOLATED.bg_subtle};
        color: {p.STATUS_ISOLATED.bright};
        border: 1px solid {p.STATUS_ISOLATED.border};
        font-weight: 600;
    }}

    QPushButton#danger_btn:hover {{
        background-color: {p.STATUS_ISOLATED.primary};
        color: #FFFFFF;
    }}

    /* Sidebar Navigation Buttons */
    QPushButton#nav_btn {{
        text-align: left;
        padding: 10px 14px;
        background-color: transparent;
        color: {p.TEXT_SECONDARY};
        border: 1px solid transparent;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
    }}

    QPushButton#nav_btn:hover {{
        background-color: {p.BG_SURFACE_HOVER};
        color: {p.TEXT_PRIMARY};
    }}

    QPushButton#nav_btn:checked {{
        background-color: #1F6FEB22;
        color: #58A6FF;
        border-left: 3px solid #58A6FF;
        font-weight: 600;
    }}

    /* ========================================================================= */
    /* Scroll Areas & Bars                                                       */
    /* ========================================================================= */
    QScrollArea {{
        border: none;
        background: transparent;
    }}

    QScrollBar:vertical {{
        background: {p.BG_CANVAS};
        width: 8px;
        margin: 0px;
    }}

    QScrollBar::handle:vertical {{
        background: {p.BORDER_DEFAULT};
        min-height: 24px;
        border-radius: 4px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {p.TEXT_MUTED};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    /* ========================================================================= */
    /* Tree Views & Tables (Diagnostics, Events)                                 */
    /* ========================================================================= */
    QTreeWidget, QTableWidget, QListView {{
        background-color: {p.BG_SURFACE};
        border: 1px solid {p.BORDER_DEFAULT};
        border-radius: 6px;
        color: {p.TEXT_PRIMARY};
        gridline-color: {p.BORDER_SUBTLE};
    }}

    QTreeWidget::item, QTableWidget::item {{
        padding: 6px 10px;
    }}

    QTreeWidget::item:selected, QTableWidget::item:selected {{
        background-color: #1F6FEB33;
        color: {p.TEXT_PRIMARY};
    }}

    QHeaderView::section {{
        background-color: {p.BG_INPUT};
        color: {p.TEXT_SECONDARY};
        padding: 6px;
        border: none;
        border-bottom: 1px solid {p.BORDER_DEFAULT};
        font-weight: 600;
        font-size: 11px;
    }}

    /* ========================================================================= */
    /* Text Inputs & Editors                                                     */
    /* ========================================================================= */
    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {p.BG_INPUT};
        border: 1px solid {p.BORDER_DEFAULT};
        border-radius: 6px;
        color: {p.TEXT_PRIMARY};
        padding: 7px 10px;
        selection-background-color: #1F6FEB;
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid {p.BORDER_ACCENT};
    }}

    /* Tooltips */
    QToolTip {{
        background-color: #1C2128;
        color: {p.TEXT_PRIMARY};
        border: 1px solid {p.BORDER_DEFAULT};
        border-radius: 4px;
        padding: 5px;
        font-size: 11px;
    }}
    """
