"""CyberDecoder - نقطة التشغيل الرئيسية."""
from __future__ import annotations

import sys
from pathlib import Path


def resource_path(rel: str) -> Path:
    """يعمل في وضع التطوير وداخل حزمة PyInstaller."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / rel


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    from cyberdecoder import APP_NAME, theme
    from cyberdecoder.gui import MainWindow

    if sys.platform == "win32":
        try:  # يجعل أيقونة شريط المهام تخص التطبيق وليس python
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("CyberDecoder.App.1")
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("CyberDecoder")
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setStyleSheet(theme.stylesheet())

    icon_file = resource_path("assets/icon.ico" if sys.platform == "win32" else "assets/icon.png")
    if icon_file.exists():
        app.setWindowIcon(QIcon(str(icon_file)))

    win = MainWindow()
    win.show()

    # فتح ملف مُمرَّر من سطر الأوامر (أو السحب على الأيقونة)
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        win.load_file(sys.argv[1])
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
