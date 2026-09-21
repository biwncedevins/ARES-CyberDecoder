"""Interpretation layer: turns raw decode results into something an analyst can read fast."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import ioc as iocmod

TYPE_AR = {
    "Text": "نص",
    "JSON": "JSON",
    "URL": "رابط URL",
    "IP": "عنوان IP",
    "Binary": "بيانات ثنائية (Binary)",
    "Empty": "فارغ",
}

# Layers that only describe / pretty-print a format, they do not peel another encoding.
DESCRIPTIVE_METHODS = ("JSON", "JWT")

LEVEL_ORDER = {"high": 0, "medium": 1, "info": 2}
LEVEL_AR = {"high": "عالية", "medium": "متوسطة", "info": "معلومة"}


@dataclass
class Finding:
    level: str          # high / medium / info
    title: str
    evidence: str = ""


_RULES: list[tuple[str, str, str]] = [
    ("high", r"powershell(?:\.exe)?[^\r\n]{0,200}?\s-(?:e|en|enc|enco|encodedcommand)\b",
     "أمر PowerShell مشفّر (-EncodedCommand)"),
    ("high", r"\b(?:iex|invoke-expression)\b", "تنفيذ نص ديناميكي (IEX / Invoke-Expression)"),
    ("high", r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer",
     "تنزيل ملف أو سكربت من الإنترنت"),
    ("high", r"certutil[^\r\n]{0,120}-(?:urlcache|decode)", "استخدام certutil للتنزيل أو فك الترميز"),
    ("high", r"mimikatz|sekurlsa|lsadump", "أدوات سرقة بيانات الاعتماد (Mimikatz)"),
    ("high", r"vssadmin[^\r\n]{0,60}delete\s+shadows|wbadmin\s+delete|bcdedit[^\r\n]{0,60}recoveryenabled\s+no",
     "تعطيل الاسترجاع (سلوك Ransomware)"),
    ("high", r"/dev/tcp/|\bnc(?:at)?(?:\.exe)?\s[^\r\n]{0,40}\s-e\s|bash\s+-i\s*>&", "نمط Reverse Shell"),
    ("high", r"amsiinitfailed|amsiutils|\bamsi\.dll\b", "محاولة تعطيل AMSI"),
    ("medium", r"frombase64string", "فك Base64 داخل السكربت (FromBase64String)"),
    ("medium", r"-(?:w|win|windowstyle)\s+(?:h|hidden)\b|\s-nop(?:rofile)?\b|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass",
     "إخفاء النافذة أو تجاوز سياسة التنفيذ في PowerShell"),
    ("medium", r"\bcmd(?:\.exe)?\s+/[ck]\b", "تشغيل أوامر عبر cmd /c"),
    ("medium", r"\b(?:mshta|regsvr32|rundll32|wscript|cscript|bitsadmin|installutil|msbuild)(?:\.exe)?\b",
     "استخدام أداة نظام موثوقة (LOLBin)"),
    ("medium", r"schtasks[^\r\n]{0,80}/create|\breg(?:\.exe)?\s+add\b|CurrentVersion\\Run",
     "محاولة بقاء دائم (Persistence)"),
    ("medium", r"\b(?:curl|wget)\b[^\r\n]{0,120}\|\s*(?:ba)?sh\b|base64\s+(?:-d|--decode)",
     "تنزيل وتنفيذ عبر shell أو فك base64"),
    ("medium", r"<script\b|javascript:|onerror\s*=|document\.cookie|String\.fromCharCode|\beval\s*\(",
     "كود JavaScript / احتمال XSS"),
    ("medium", r"union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|xp_cmdshell|\.\./\.\./|/etc/passwd",
     "نمط هجوم ويب (SQLi / Path Traversal)"),
    ("medium", r"-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----", "مفتاح أو شهادة بصيغة PEM"),
    ("info", r"\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]", "قد يحتوي على بيانات اعتماد"),
]
_COMPILED = [(lvl, re.compile(rx, re.IGNORECASE), title) for lvl, rx, title in _RULES]


def scan_text(text: str, limit: int = 1_000_000) -> list[Finding]:
    text = text[:limit]
    out: list[Finding] = []
    for lvl, rx, title in _COMPILED:
        m = rx.search(text)
        if m:
            ev = " ".join(m.group(0).split())[:90]
            out.append(Finding(lvl, title, ev))
    return out


def merge_findings(groups: list[list[Finding]]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for g in groups:
        for f in g:
            seen.setdefault(f.title, f)
    return sorted(seen.values(), key=lambda f: LEVEL_ORDER[f.level])


# ---------------------------------------------------------------- Arabic wording helpers

def ar_layers(n: int) -> str:
    if n == 1:
        return "طبقة واحدة"
    if n == 2:
        return "طبقتين"
    if 3 <= n <= 10:
        return f"{n} طبقات"
    return f"{n} طبقة"


def ar_items(n: int, one: str, two: str, few: str, many: str) -> str:
    if n == 1:
        return f"{one} واحد"
    if n == 2:
        return two
    if 3 <= n <= 10:
        return f"{n} {few}"
    return f"{n} {many}"


def summarize(a) -> list[str]:
    """Human readable (Arabic) summary lines for an Analysis object."""
    lines: list[str] = []
    decode_layers = [l for l in a.layers if l.method not in DESCRIPTIVE_METHODS]
    descr_layers = [l for l in a.layers if l.method in DESCRIPTIVE_METHODS]
    tname = TYPE_AR.get(a.final_type, a.final_type)

    if decode_layers:
        chain = " → ".join(l.method for l in decode_layers)
        lines.append(f"تم فك {ar_layers(len(decode_layers))} بنجاح ({chain}).")
    elif descr_layers and descr_layers[0].method == "JWT":
        lines.append("الإدخال عبارة عن JWT وتم تفكيك الـ Header والـ Payload.")
    elif descr_layers:
        lines.append("الإدخال بصيغة JSON صالحة ولا يحتاج إلى فك ترميز.")
    elif a.final_type == "Binary":
        lines.append("الإدخال بيانات ثنائية ولم يُكتشف ترميز معروف على مستوى الملف كاملًا.")
    else:
        lines.append("لم يُكتشف ترميز معروف على مستوى الإدخال كاملًا؛ يبدو نصًا عاديًا.")

    if a.final_type == "Binary":
        lines.append(f"الناتج النهائي: {tname} — {a.final_detail}.")
    else:
        lines.append(f"الناتج النهائي: {tname}.")

    if a.embedded:
        lines.append(f"عُثر على {ar_items(len(a.embedded), 'مقطع', 'مقطعين', 'مقاطع', 'مقطعًا')} "
                     "مشفّرًا داخل النص وتم فكّه.")

    total = a.ioc_count
    if total:
        parts = [f"{len(v)} {iocmod.TYPE_LABELS[k]}" for k, v in a.iocs.items()]
        lines.append(f"تم استخراج {total} مؤشر (IOC): " + "، ".join(parts) + ".")
    else:
        lines.append("لا توجد مؤشرات (IOC) ظاهرة في النتيجة.")

    high = [f for f in a.findings if f.level == "high"]
    if high:
        lines.append(f"تنبيه: {len(high)} ملاحظة عالية الخطورة، راجع تبويب «ملاحظات».")

    lines.extend(a.warnings)
    return lines
