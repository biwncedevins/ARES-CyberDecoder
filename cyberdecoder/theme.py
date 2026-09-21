"""Visual identity: deep ink-blue surfaces, amber for actions, teal for confident results."""

INK = "#0E1420"        # window background
SLATE = "#151D2C"      # editors / panels
RAISED = "#1B2538"     # buttons / banner
LINE = "#263247"       # borders
TEXT = "#E7ECF4"
MUTED = "#8A97AD"
AMBER = "#F2B544"      # primary action
AMBER_HI = "#FFC65A"
TEAL = "#4FD1C5"       # high confidence / final result
CORAL = "#FF7A6B"      # danger / low confidence
SKY = "#6CA8FF"
SELECT = "#2A3552"

LEVEL_COLORS = {"high": CORAL, "medium": AMBER, "info": SKY}


def confidence_color(conf: int) -> str:
    if conf >= 80:
        return TEAL
    if conf >= 60:
        return AMBER
    return CORAL


def stylesheet() -> str:
    return f"""
QWidget {{ background: {INK}; color: {TEXT}; }}
QLabel {{ background: transparent; }}
QLabel#appTitle {{ font-size: 15pt; font-weight: 700; color: {AMBER}; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#panelTitle {{ font-weight: 600; color: {TEXT}; }}
QLabel#banner {{ background: {RAISED}; border: 1px solid {LINE}; border-radius: 10px; padding: 12px 14px; }}

QPlainTextEdit, QTextBrowser {{
    background: {SLATE}; border: 1px solid {LINE}; border-radius: 8px; padding: 8px;
    selection-background-color: {AMBER}; selection-color: #1B1300;
    placeholder-text-color: {MUTED};
}}
QPlainTextEdit:focus {{ border: 1px solid {AMBER}; }}

QPushButton, QToolButton {{
    background: {RAISED}; border: 1px solid {LINE}; border-radius: 8px; padding: 7px 16px;
}}
QPushButton:hover, QToolButton:hover {{ border-color: {AMBER}; }}
QPushButton:pressed, QToolButton:pressed {{ background: {SLATE}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {LINE}; }}
QPushButton#primary {{ background: {AMBER}; color: #1B1300; border: 1px solid {AMBER}; font-weight: 700; padding: 7px 22px; }}
QPushButton#primary:hover {{ background: {AMBER_HI}; }}
QPushButton#primary:disabled {{ background: #6b5628; color: #241a05; border-color: #6b5628; }}
QPushButton#flat {{ background: transparent; border: none; color: {AMBER}; padding: 2px 6px; }}
QPushButton#flat:hover {{ color: {AMBER_HI}; text-decoration: underline; }}
QToolButton::menu-indicator {{ image: none; width: 0px; }}

QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 8px; background: {SLATE}; top: -1px; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent; color: {MUTED}; padding: 9px 16px; margin: 0 2px;
    border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {TEXT}; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {AMBER}; }}

QTableWidget, QTreeWidget {{
    background: {SLATE}; border: 1px solid {LINE}; border-radius: 8px;
    gridline-color: {LINE}; alternate-background-color: #182236; outline: 0;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; }}
QTableWidget::item:selected, QTreeWidget::item:selected {{ background: {SELECT}; color: {TEXT}; }}
QHeaderView::section {{
    background: {RAISED}; color: {MUTED}; padding: 7px 10px; border: none; border-bottom: 1px solid {LINE};
}}
QTableCornerButton::section {{ background: {RAISED}; border: none; }}

QSpinBox {{
    background: {SLATE}; border: 1px solid {LINE}; border-radius: 6px; padding: 4px 8px; min-width: 52px;
}}
QSpinBox:focus {{ border-color: {AMBER}; }}
QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {LINE}; border-radius: 4px; background: {SLATE}; }}
QCheckBox::indicator:checked {{ background: {AMBER}; border-color: {AMBER}; }}

QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #34445F; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {LINE}; border-radius: 4px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: #34445F; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QSplitter::handle {{ background: {INK}; }}
QSplitter::handle:horizontal {{ width: 10px; }}
QSplitter::handle:vertical {{ height: 8px; }}

QStatusBar {{ background: {SLATE}; color: {MUTED}; border-top: 1px solid {LINE}; }}
QStatusBar::item {{ border: none; }}

QMenu {{ background: {RAISED}; border: 1px solid {LINE}; padding: 4px; }}
QMenu::item {{ padding: 7px 24px; border-radius: 4px; }}
QMenu::item:selected {{ background: {SELECT}; }}
QMenu::separator {{ height: 1px; background: {LINE}; margin: 4px 8px; }}

QToolTip {{ background: {RAISED}; color: {TEXT}; border: 1px solid {LINE}; padding: 4px 8px; }}
QMessageBox {{ background: {INK}; }}
"""
