"""CyberDecoder core engine.

Workflow:  INPUT -> DETECT -> DECODE -> VALIDATE -> NEXT LAYER -> EXTRACT -> REPORT

Every detector receives the current bytes (and their text view when they are textual) and returns
a Detection with a confidence score. The engine keeps applying the best detection until nothing
sensible is left, a safe depth limit is reached, or a loop is detected.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import ipaddress
import json
import re
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import unquote_to_bytes

from . import interpret
from . import ioc as iocmod

MAX_OUTPUT = 32 * 1024 * 1024        # per-layer output cap (zip-bomb protection)
DEFAULT_MAX_DEPTH = 12
DEFAULT_MIN_CONF = 50
EMBEDDED_TEXT_LIMIT = 1024 * 1024
EMBEDDED_MAX_TOKENS = 300


# ====================================================================== data model

@dataclass
class Detection:
    method: str
    confidence: int
    output: bytes
    notes: list[str] = field(default_factory=list)
    terminal: bool = False        # JSON / JWT: describe a format, do not peel further
    priority: int = 0


@dataclass
class Layer:
    index: int
    method: str
    confidence: int
    in_size: int
    out_size: int
    out_type: str
    out_detail: str
    notes: list[str]
    data: bytes = field(repr=False, default=b"")


@dataclass
class Embedded:
    offset: int
    token: str
    analysis: "Analysis"


@dataclass
class Analysis:
    source: str
    original: bytes
    original_type: str = "Empty"
    original_detail: str = ""
    layers: list[Layer] = field(default_factory=list)
    final: bytes = b""
    final_type: str = "Empty"
    final_detail: str = ""
    iocs: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    findings: list[interpret.Finding] = field(default_factory=list)
    embedded: list[Embedded] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    stop_reason: str = "done"
    elapsed_ms: float = 0.0
    sha256_original: str = ""
    sha256_final: str = ""
    max_depth: int = DEFAULT_MAX_DEPTH
    min_conf: int = DEFAULT_MIN_CONF

    @property
    def ioc_count(self) -> int:
        return sum(len(v) for v in self.iocs.values())

    @property
    def decode_layer_count(self) -> int:
        return sum(1 for l in self.layers if l.method not in interpret.DESCRIPTIVE_METHODS)


# ====================================================================== text helpers

def printable_ratio(text: str) -> float:
    if not text:
        return 1.0
    sample = text[:65536]
    good = sum(1 for c in sample if c.isprintable() or c.isspace())
    return good / len(sample)


def decode_text(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """Return (text, encoding) when *data* is textual, otherwise (None, None)."""
    if not data:
        return "", "utf-8"
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig"), "utf-8-sig"
        except UnicodeDecodeError:
            pass
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            return None, None
    n = len(data)
    if n >= 4 and n % 2 == 0:               # BOM-less UTF-16 that is mostly ASCII (PowerShell -enc)
        even, odd = data[0::2], data[1::2]
        try:
            if even.count(0) == 0 and odd.count(0) >= len(odd) * 0.5:
                return data.decode("utf-16-le"), "utf-16le"
            if odd.count(0) == 0 and even.count(0) >= len(even) * 0.5:
                return data.decode("utf-16-be"), "utf-16be"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return None, None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text_meaningful(text: str) -> bool:
    body = [c for c in text if not c.isspace()]
    if not body:
        return False
    return sum(1 for c in body if c.isalnum()) / len(body) >= 0.35


# ====================================================================== magic / classify

_MAGICS = [
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive (DOCX/XLSX/JAR/APK...)"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"\x1f\x8b", "Gzip stream"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office / MSI)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xfd7zXZ\x00", "XZ stream"),
    (b"BZh", "Bzip2 stream"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O universal"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
]


def _is_pe(d: bytes) -> bool:
    if d[:2] != b"MZ" or len(d) < 64:
        return False
    off = int.from_bytes(d[0x3C:0x40], "little")
    return off + 4 <= len(d) and d[off:off + 4] == b"PE\x00\x00"


def _is_zlib(d: bytes) -> bool:
    if len(d) < 6 or d[0] != 0x78 or ((d[0] << 8) | d[1]) % 31 != 0:
        return False
    try:
        zlib.decompressobj().decompress(d, 1 << 16)
        return True
    except zlib.error:
        return False


def identify_magic(data: bytes) -> Optional[str]:
    if _is_pe(data):
        return "Windows PE executable (EXE/DLL)"
    for sig, label in _MAGICS:
        if data.startswith(sig):
            return label
    if _is_zlib(data):
        return "zlib stream"
    return None


_URL_FULL = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]{1,15}://\S+$")


def classify(data: bytes) -> tuple[str, str]:
    """Return (type, detail) with type in Text / JSON / URL / IP / Binary / Empty."""
    if not data:
        return "Empty", ""
    text, enc = decode_text(data)
    if text is None or printable_ratio(text) < 0.9:
        return "Binary", identify_magic(data) or "بيانات ثنائية غير معروفة"
    s = text.strip()
    if s[:1] in ("{", "["):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return "JSON", f"object · {len(obj)} keys"
            if isinstance(obj, list):
                return "JSON", f"array · {len(obj)} items"
        except (ValueError, RecursionError):
            pass
    if _URL_FULL.match(s):
        return "URL", ""
    try:
        ip = ipaddress.ip_address(s)
        return "IP", f"IPv{ip.version}"
    except ValueError:
        pass
    lines = text.count("\n") + 1
    return "Text", f"{enc} · {lines} line{'s' if lines != 1 else ''}"


def _assess(raw: bytes) -> tuple[bytes, str, list[str]]:
    """Judge freshly decoded bytes. kind: 'magic' | 'text' | 'unknown'."""
    if not raw:
        return raw, "unknown", []
    magic = identify_magic(raw)
    if magic:
        return raw, "magic", [f"المحتوى: {magic}"]
    text, enc = decode_text(raw)
    if text is not None and printable_ratio(text) >= 0.95 and _text_meaningful(text):
        if enc in ("utf-16", "utf-16le", "utf-16be"):
            return text.encode("utf-8"), "text", ["ترميز UTF-16 → تم التحويل إلى UTF-8"]
        if enc == "utf-8-sig":
            return text.encode("utf-8"), "text", []
        return raw, "text", []
    return raw, "unknown", []


def _clean_token(text: str) -> str:
    s = text.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _letters_ratio(data: bytes) -> float:
    text, _ = decode_text(data)
    if not text:
        return 0.0
    sample = text[:2000]
    return sum(1 for c in sample if c.isalpha() or c == " ") / len(sample)


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


# ====================================================================== detectors
# signature: fn(data: bytes, text: Optional[str]) -> Optional[Detection]

def _inflate(data: bytes, wbits: int) -> tuple[bytes, bool]:
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, MAX_OUTPUT)
    return out, bool(d.unconsumed_tail)


def det_gzip(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if data[:2] != b"\x1f\x8b":
        return None
    out, truncated = _inflate(data, 31)
    notes = [f"الحجم بعد الفك: {fmt_size(len(out))}"]
    if truncated:
        notes.append(f"تم اقتطاع الناتج عند {fmt_size(MAX_OUTPUT)} (حماية من Zip bomb)")
    return Detection("Gzip", 97, out, notes)


def det_zlib(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if not _is_zlib(data):
        return None
    out, truncated = _inflate(data, 15)
    notes = [f"الحجم بعد الفك: {fmt_size(len(out))}"]
    if truncated:
        notes.append(f"تم اقتطاع الناتج عند {fmt_size(MAX_OUTPUT)} (حماية من Zip bomb)")
    return Detection("Zlib", 95, out, notes)


def _b64url_json(part: str):
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    return json.loads(raw.decode("utf-8"))


def _ts(value) -> Optional[str]:
    try:
        v = float(value)
        if v > 1e11:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*$")


def det_jwt(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    s = re.sub(r"^bearer\s+", "", _clean_token(text), flags=re.IGNORECASE)
    if not _JWT_RE.match(s):
        return None
    h, p, sig = s.split(".")
    try:
        header, payload = _b64url_json(h), _b64url_json(p)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    notes = []
    alg = str(header.get("alg", "?"))
    notes.append(f"الخوارزمية: {alg}")
    if alg.lower() == "none" or not sig:
        notes.append("تنبيه: التوقيع غير موجود (alg=none)")
    for key, label in (("iat", "أُصدر"), ("nbf", "يبدأ"), ("exp", "ينتهي")):
        if key in payload and (t := _ts(payload[key])):
            notes.append(f"{label}: {t}")
    if "exp" in payload:
        try:
            if float(payload["exp"]) < time.time():
                notes.append("التوكن منتهي الصلاحية")
        except (TypeError, ValueError):
            pass
    notes.append("لم يتم التحقق من التوقيع")
    doc = {"header": header, "payload": payload, "signature": sig}
    out = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
    return Detection("JWT", 98, out, notes, terminal=True)


def det_json(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    s = text.strip()
    if not s:
        return None
    try:
        if s[0] in "{[":
            obj = json.loads(s)
            if not isinstance(obj, (dict, list)):
                return None
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            kind = f"object · {len(obj)} keys" if isinstance(obj, dict) else f"array · {len(obj)} items"
            return Detection("JSON", 95, pretty.encode("utf-8"), [f"JSON صالح ({kind})"], terminal=True)
        if s[0] == '"' and s[-1] == '"' and len(s) > 2 and "\\" in s:
            inner = json.loads(s)
            if isinstance(inner, str):
                return Detection("JSON String", 80, inner.encode("utf-8"), ["نص JSON مُهرَّب (escaped)"])
    except (ValueError, RecursionError):
        return None
    return None


_B64_STD = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64_URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def _join_wrapped(s: str) -> Optional[str]:
    """Accept line-wrapped Base64 (MIME/PEM style: equal-length lines)."""
    lines = [l for l in s.splitlines()]
    if len(lines) < 2 or any(not l for l in lines):
        return None
    width = len(lines[0])
    if width < 16 or any(len(l) != width for l in lines[:-1]) or len(lines[-1]) > width:
        return None
    return "".join(lines)


def det_base64(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    s = _clean_token(text)
    if len(s) < 8 or " " in s or "\t" in s:
        return None
    if "\n" in s or "\r" in s:
        s = _join_wrapped(s)
        if s is None:
            return None
    urlsafe = False
    if _B64_STD.match(s):
        pass
    elif _B64_URL.match(s):
        urlsafe = True
    else:
        return None
    body = s.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        raw = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(padded)
    except (binascii.Error, ValueError):
        return None

    classes = sum([
        any(c.islower() for c in s), any(c.isupper() for c in s),
        any(c.isdigit() for c in s), any(c in "+/-_" for c in s),
    ])
    out, kind, notes = _assess(raw)
    if kind == "unknown":
        if len(s) >= 24 and classes >= 3:      # keep as a weak hint only (below default threshold)
            return Detection("Base64", 40, raw, ["ناتج ثنائي غير معروف (ربما بيانات مشفّرة)"])
        return None

    if kind == "magic":
        conf = 88
    else:
        conf = 55
        conf += 8 if len(s) >= 16 else 0
        conf += 7 if len(s) >= 32 else 0
        conf += 10 if "=" in s else 0
        if classes >= 3:
            conf += 8
        elif classes == 1:
            conf -= 20
        elif "=" not in s and not any(c.isdigit() for c in s):
            conf -= 12
        if _letters_ratio(out) >= 0.7:
            conf += 8
        if len(raw) < 4:
            conf -= 15
    conf = max(0, min(conf, 99))
    if urlsafe:
        notes.insert(0, "Base64 URL-safe")
    if len(body) % 4:
        notes.insert(0, "بدون padding (تم إكماله)")
    return Detection("Base64", conf, out, notes)


def _parse_hex(s: str) -> Optional[tuple[bytes, str]]:
    try:
        if re.fullmatch(r"(?:\\x[0-9a-fA-F]{2})+", s):
            return bytes.fromhex(s.replace("\\x", "")), "escape"
        if re.fullmatch(r"\s*(?:0x[0-9a-fA-F]{1,2}[\s,;]*)+", s, re.IGNORECASE):
            toks = re.findall(r"0x([0-9a-fA-F]{1,2})", s, re.IGNORECASE)
            return bytes(int(t, 16) for t in toks), "0x"
        m = re.fullmatch(r"0x([0-9a-fA-F]+)", s, re.IGNORECASE)
        if m and len(m.group(1)) % 2 == 0:
            return bytes.fromhex(m.group(1)), "0x"
        if re.fullmatch(r"[0-9a-fA-F]{2}(?:[\s:,\-]+[0-9a-fA-F]{2})+", s):
            return bytes.fromhex(re.sub(r"[\s:,\-]+", "", s)), "sep"
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
            return bytes.fromhex(s), "plain"
    except ValueError:
        return None
    return None


def det_hex(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    s = _clean_token(text)
    if len(s) < 8:
        return None
    parsed = _parse_hex(s)
    if not parsed:
        return None
    raw, style = parsed
    if len(raw) < 2 or (style == "plain" and len(raw) < 4):
        return None
    explicit = style in ("escape", "0x")
    out, kind, notes = _assess(raw)
    if kind == "unknown":
        if not explicit:
            return None
        notes = ["بيانات ثنائية"]
        conf = 82
    elif kind == "magic":
        conf = 90
    else:
        conf = 97 if style == "escape" else 95 if style == "0x" else 66
        if not explicit:
            conf += 6 if any(c in "abcdefABCDEF" for c in s) else 0
            conf += 6 if len(s) >= 16 else 0
            conf += 4 if len(s) >= 32 else 0
            conf += 6 if style == "sep" else 0
            conf += 6 if _letters_ratio(out) >= 0.7 else 0
            if s.isdigit():                       # numbers, not hex text
                conf = min(conf, 40)
    return Detection("Hex", min(conf, 97), out, notes)


_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def det_url(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    hits = _PCT.findall(text)
    if not hits:
        return None
    out = unquote_to_bytes(text)
    if out == data:
        return None
    ratio = len(hits) * 3 / max(len(text.strip()), 1)
    conf = 55 + min(20, len(hits) * 2) + (15 if ratio > 0.3 else 0)
    dtext, _ = decode_text(out)
    if dtext is None or printable_ratio(dtext) < 0.9:
        if ratio <= 0.5 or len(hits) < 4:
            return None
        conf -= 10
    return Detection("URL Encoding", min(conf, 96), out, [f"{len(hits)} رمز من نوع \u2066%XX\u2069"])


_ESC_RE = re.compile(
    r"\\u\{([0-9a-fA-F]{1,6})\}|\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|%u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})"
)


def _decode_escapes(s: str) -> tuple[bytes, int, int]:
    toks = list(_ESC_RE.finditer(s))
    out = bytearray()
    last = count = covered = 0
    i = 0
    while i < len(toks):
        m = toks[i]
        out += s[last:m.start()].encode("utf-8", "replace")
        if m.group(5) is not None:                        # \xNN  -> raw byte
            out.append(int(m.group(5), 16))
            end = m.end()
        else:
            cp = int(next(g for g in m.groups()[:4] if g is not None), 16)
            end = m.end()
            if 0xD800 <= cp <= 0xDBFF and i + 1 < len(toks) and toks[i + 1].start() == end:
                lo_hex = toks[i + 1].group(3) or toks[i + 1].group(4)
                if lo_hex and 0xDC00 <= int(lo_hex, 16) <= 0xDFFF:
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (int(lo_hex, 16) - 0xDC00)
                    end = toks[i + 1].end()
                    i += 1
            try:
                out += chr(cp).encode("utf-8", "replace")
            except (ValueError, OverflowError):
                out += b"?"
        covered += end - m.start()
        last = end
        count += 1
        i += 1
    out += s[last:].encode("utf-8", "replace")
    return bytes(out), count, covered


def det_unicode(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None or ("\\" not in text and "%u" not in text):
        return None
    out, count, covered = _decode_escapes(text)
    if count == 0 or out == data:
        return None
    conf = 62 + min(30, count * 3) + (6 if covered >= len(text) * 0.5 else 0)
    return Detection("Unicode Escapes", min(conf, 96), out, [f"{count} رمز escape"])


_HTML_ENT = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,8});")


def det_html(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None or "&" not in text:
        return None
    hits = _HTML_ENT.findall(text)
    if not hits:
        return None
    out = html.unescape(text)
    if out == text:
        return None
    return Detection("HTML Entities", min(55 + len(hits) * 4, 90), out.encode("utf-8"), [f"{len(hits)} كيان HTML"])


_B32 = re.compile(r"^[A-Z2-7]{8,}={0,6}$")


def det_base32(data: bytes, text: Optional[str]) -> Optional[Detection]:
    if text is None:
        return None
    s = _clean_token(text)
    if not _B32.match(s) or " " in s:
        return None
    body = s.rstrip("=")
    padded = body + "=" * (-len(body) % 8)
    try:
        raw = base64.b32decode(padded)
    except (binascii.Error, ValueError):
        return None
    out, kind, notes = _assess(raw)
    if kind != "text" or len(raw) < 5 or _letters_ratio(out) < 0.6:
        return None
    conf = 62 + (10 if "=" in s else 0) + (8 if len(s) >= 32 else 0)
    return Detection("Base32", min(conf, 92), out, notes)


# order == tie-break priority (earlier wins on equal confidence)
DETECTORS: list[Callable[[bytes, Optional[str]], Optional[Detection]]] = [
    det_gzip, det_zlib, det_jwt, det_json, det_base64, det_hex, det_url, det_unicode, det_html, det_base32,
]


def run_detectors(data: bytes) -> list[Detection]:
    if not data:
        return []
    text, _ = decode_text(data)
    if text is not None and printable_ratio(text) < 0.9:
        text = None
    found: list[Detection] = []
    for prio, fn in enumerate(DETECTORS):
        try:
            d = fn(data, text)
        except Exception:                # a broken detector must never crash the analysis
            d = None
        if d is not None:
            d.priority = prio
            found.append(d)
    found.sort(key=lambda d: (-d.confidence, d.priority))
    return found


# ====================================================================== embedded scan

_EMB_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"),
    re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){8,}(?![0-9A-Za-z])"),
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}|(?:\\u[0-9a-fA-F]{4}){2,}|(?:%u[0-9a-fA-F]{4}){2,}"),
    re.compile(r"[^\s\"'<>]*(?:%[0-9A-Fa-f]{2}[^\s\"'<>]*){2,}"),
]


def _find_tokens(text: str) -> list[tuple[int, int]]:
    spans = []
    for pat in _EMB_PATTERNS:
        for m in pat.finditer(text):
            spans.append((m.start(), m.end()))
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    picked, last_end = [], -1
    for s, e in spans:
        if s >= last_end:
            picked.append((s, e))
            last_end = e
    return picked


def find_embedded(text: str, min_conf: int) -> list[Embedded]:
    text = text[:EMBEDDED_TEXT_LIMIT]
    whole = text.strip()
    results: list[Embedded] = []
    seen: set[str] = set()
    for s, e in _find_tokens(text)[:EMBEDDED_MAX_TOKENS]:
        token = text[s:e]
        if token in seen or token == whole:
            continue
        seen.add(token)
        sub = analyze(token.encode("utf-8"), source="embedded", max_depth=8,
                      min_conf=max(min_conf, 60), scan_embedded=False, _nested=True)
        real = [l for l in sub.layers if l.method not in interpret.DESCRIPTIVE_METHODS]
        if real and sub.final != token.encode("utf-8"):
            results.append(Embedded(s, token, sub))
        if len(results) >= 200:
            break
    return results


# ====================================================================== analysis

def _ioc_view(data: bytes) -> str:
    text, _ = decode_text(data[:iocmod.MAX_TEXT])
    if text is None or printable_ratio(text) < 0.9:
        return ""
    s = text.strip()
    if s[:1] in ("{", "[") and len(s) < iocmod.MAX_TEXT:
        try:
            strings: list[str] = []

            def walk(o):
                if isinstance(o, str):
                    strings.append(o)
                elif isinstance(o, dict):
                    for k, v in o.items():
                        walk(k)
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)

            walk(json.loads(s))
            return "\n".join(strings)
        except (ValueError, RecursionError):
            pass
    return text


def analyze(
    data: bytes,
    source: str = "input",
    max_depth: int = DEFAULT_MAX_DEPTH,
    min_conf: int = DEFAULT_MIN_CONF,
    scan_embedded: bool = True,
    _nested: bool = False,
) -> Analysis:
    t0 = time.perf_counter()
    a = Analysis(source=source, original=data, max_depth=max_depth, min_conf=min_conf)
    a.original_type, a.original_detail = classify(data)
    a.sha256_original = _sha(data)

    current = data
    seen = {a.sha256_original}
    exhausted = True

    for _ in range(max_depth):
        dets = run_detectors(current)
        if not dets:
            exhausted = False
            break
        best = dets[0]
        if best.confidence < min_conf:
            if not _nested:
                for d in dets:
                    if d.confidence >= 30:
                        a.hints.append(
                            f"اكتُشف {d.method} محتمل بثقة {d.confidence}% لكنه أقل من الحد ({min_conf}%) فلم يُطبَّق."
                        )
            exhausted = False
            break
        out = best.output
        if not best.terminal:
            if out == current:
                exhausted = False
                break
            h = _sha(out)
            if h in seen:
                a.warnings.append("تم اكتشاف حلقة تكرار (Loop) وتم إيقاف الفك تلقائيًا.")
                a.stop_reason = "loop"
                exhausted = False
                break
            seen.add(h)
        otype, odetail = classify(out)
        a.layers.append(Layer(
            index=len(a.layers) + 1, method=best.method, confidence=best.confidence,
            in_size=len(current), out_size=len(out), out_type=otype, out_detail=odetail,
            notes=best.notes, data=out,
        ))
        current = out
        if best.terminal:
            exhausted = False
            break

    if exhausted:
        rest = run_detectors(current)
        if rest and rest[0].confidence >= min_conf:
            a.warnings.append(f"تم الوصول إلى الحد الأقصى للعمق ({max_depth}) وما زال هناك ترميز محتمل.")
            a.stop_reason = "max_depth"

    a.final = current
    a.final_type, a.final_detail = classify(current)
    a.sha256_final = _sha(current)

    if not _nested:
        if scan_embedded:
            ftext, _ = decode_text(current)
            if ftext is not None and a.final_type in ("Text", "JSON"):
                a.embedded = find_embedded(ftext, min_conf)
        _finish(a)

    a.elapsed_ms = (time.perf_counter() - t0) * 1000
    return a


def _finish(a: Analysis) -> None:
    """IOC extraction + findings (the EXTRACT / REPORT stages)."""
    coll = iocmod.Collector()
    coll.add_text(_ioc_view(a.original), "الإدخال")
    groups = []
    view = _ioc_view(a.original)
    if view:
        groups.append(interpret.scan_text(view))
    for l in a.layers:
        v = _ioc_view(l.data)
        if v:
            coll.add_text(v, f"طبقة {l.index}")
            groups.append(interpret.scan_text(v))
    for k, e in enumerate(a.embedded, 1):
        for l in e.analysis.layers:
            v = _ioc_view(l.data)
            if v:
                coll.add_text(v, f"مقطع {k}")
                groups.append(interpret.scan_text(v))
    a.iocs = coll.result()
    a.findings = interpret.merge_findings(groups)
    if a.final_type == "Binary" and "PE executable" in a.final_detail:
        a.findings.insert(0, interpret.Finding(
            "high", "الناتج ملف تنفيذي Windows (PE)", "لا تشغّله؛ احفظه وحلّله داخل بيئة معزولة"))
    a.findings.sort(key=lambda f: interpret.LEVEL_ORDER[f.level])
