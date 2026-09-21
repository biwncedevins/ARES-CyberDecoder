import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from cyberdecoder import engine, gui  # noqa: E402

_app = QApplication.instance() or QApplication([])


class GuiSmoke(unittest.TestCase):
    def test_sample_roundtrip(self):
        w = gui.MainWindow()
        w.input.setPlainText(gui.build_sample())
        a = engine.analyze(gui.build_sample().encode())
        w._render(a)
        self.assertEqual([l.method for l in a.layers], ["Base64", "Gzip", "Base64", "URL Encoding"])
        self.assertGreater(a.ioc_count, 0)
        self.assertEqual(w.tabs.count(), 6)


if __name__ == "__main__":
    unittest.main()
