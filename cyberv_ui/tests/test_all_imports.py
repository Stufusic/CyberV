# -*- coding: utf-8 -*-
"""
Kiểm thử toàn vẹn import toàn bộ các module trong gói cyberv_ui.
Đảm bảo không module nào bị lỗi relative import hoặc thiếu dependency khi đóng gói.
"""

import importlib
import pkgutil
import pytest

import cyberv_ui


def test_all_cyberv_ui_modules_importable():
    """Tất cả các module con trong cyberv_ui phải import thành công."""
    errors = []
    for mod in pkgutil.walk_packages(cyberv_ui.__path__, cyberv_ui.__name__ + "."):
        try:
            importlib.import_module(mod.name)
        except Exception as exc:
            errors.append(f"{mod.name}: {type(exc).__name__}: {exc}")

    assert not errors, f"Phat hien cac module khong the import:\n" + "\n".join(errors)


def test_isolation_page_import():
    """Kiem tra cu the module isolation_page va lop IsolationPage."""
    from cyberv_ui.ui.pages.isolation_page import IsolationPage, REFRESH_MS
    from cyberv_ui.services.isolation_service import IsolationService

    assert REFRESH_MS == 5000
    assert IsolationPage is not None
    assert IsolationService is not None
