"""IOC extraction: URLs / Domains / IPv4 / Windows paths / Emails / Registry / Hashes.

Everything here is pure standard library and works fully offline.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_TEXT = 2 * 1024 * 1024      # never scan more than 2 MB of text per source
MAX_PER_TYPE = 500

TYPE_ORDER = ["url", "domain", "ipv4", "email", "path", "registry", "hash"]
TYPE_LABELS = {
    "url": "URLs",
    "domain": "Domains",
    "ipv4": "IPv4",
    "email": "Emails",
    "path": "Windows Paths",
    "registry": "Registry Keys",
    "hash": "Hashes",
}

# Well-known TLDs only: keeps file names such as "run.exe" or "tool.py" out of the domain list.
KNOWN_TLDS = frozenset("""
com net org info biz edu gov mil int io co me tv xyz top site online store tech app dev cloud club
live pro name mobi asia icu vip shop fun link click work today world news blog page email space
website ws to ly gl gd sx su ru cn tk ml ga cf gq onion ai cc pw tw hk ac am fm gg im is la lu nu vc
us uk de fr it es nl be ch at se no dk fi cz sk hu ro bg gr tr ua by kz ir iq sa ae eg il jp kr in pk
bd id my sg th vn ph au nz ca br ar mx cl za ng ke ma dz tn ps qa kw om bh jo lb sy ye sd eu cat ie
pt lt lv ee si hr rs ba mk al xin rest bid cyou monster buzz cam best help support solutions network
systems digital center agency team
""".split())

_TRAIL = ".,;:!?'\")]}>"

URL_RE = re.compile(
    r"\b(?:https?|ftps?|sftp|wss?|smb|tcp)://[^\s<>\"'`\\^|{}]+", re.IGNORECASE
)
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)")
DOMAIN_RE = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])(?!\.\w)",
    re.IGNORECASE,
)
IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\w|\.\w)"
)
WINPATH_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n;,]{0,63}[^\\/:*?\"<>|\s;,]\\)*(?:[^\\/:*?\"<>|\s,;'`()\[\]{}]+)?"
)
UNC_RE = re.compile(r"(?<!\\)\\\\[A-Za-z0-9_.$-]{1,63}\\[^\\/:*?\"<>|\s]+(?:\\[^\\/:*?\"<>|\s]+)*")
ENVPATH_RE = re.compile(
    r"%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE|PROGRAMDATA|PROGRAMFILES|WINDIR|SYSTEMROOT|"
    r"SYSTEMDRIVE|HOMEPATH|PUBLIC)%\\[^\s\"'<>|]*",
    re.IGNORECASE,
)
REGISTRY_RE = re.compile(
    r"\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_CLASSES_ROOT|EY_USERS|EY_CURRENT_CONFIG|LM|CU|CR|U)"
    r"\\[^\s\"'<>|]+",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"(?<![A-Za-z0-9])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![A-Za-z0-9])")

# "hxxp://evil[.]com" style defanging is reversed before scanning.
_REFANG = [
    (re.compile(r"\bhxxp(s?)(?:\[:\]|:)//", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


class _Bucket:
    def __init__(self) -> None:
        self.items: list[str] = []
        self._seen: set[str] = set()

    def add(self, value: str) -> None:
        if value and value not in self._seen and len(self.items) < MAX_PER_TYPE:
            self._seen.add(value)
            self.items.append(value)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def extract(text: str) -> dict[str, list[str]]:
    """Return {type: [values]} in order of first appearance."""
    text = refang(text[:MAX_TEXT])
    b = {k: _Bucket() for k in TYPE_ORDER}

    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAIL)
        if len(url) < 10:
            continue
        b["url"].add(url)
        host = _host_of(url)
        if host:
            if _valid_ipv4(host):
                b["ipv4"].add(host)
            elif "." in host:
                b["domain"].add(host)

    for m in EMAIL_RE.finditer(text):
        dom = m.group(1).lower()
        if dom.rsplit(".", 1)[-1] in KNOWN_TLDS:
            b["email"].add(m.group(0))
            b["domain"].add(dom)

    for m in DOMAIN_RE.finditer(text):
        if m.group(2).lower() in KNOWN_TLDS:
            b["domain"].add(m.group(1).lower())

    for m in IPV4_RE.finditer(text):
        b["ipv4"].add(m.group(0))

    for rx in (WINPATH_RE, UNC_RE, ENVPATH_RE):
        for m in rx.finditer(text):
            p = m.group(0).rstrip(_TRAIL + " ")
            if len(p) > 3:
                b["path"].add(p)

    for m in REGISTRY_RE.finditer(text):
        b["registry"].add(m.group(0).rstrip(_TRAIL))

    for m in HASH_RE.finditer(text):
        v = m.group(0).lower()
        if v.isdigit() or len(set(v)) < 5:
            continue
        b["hash"].add(v)

    return {k: b[k].items for k in TYPE_ORDER}


class Collector:
    """Merges IOCs from several texts and remembers where each one was first seen."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str]] = {k: {} for k in TYPE_ORDER}

    def add_text(self, text: str, source: str) -> None:
        if not text:
            return
        for typ, values in extract(text).items():
            slot = self._data[typ]
            for v in values:
                if v not in slot and len(slot) < MAX_PER_TYPE:
                    slot[v] = source

    def result(self) -> dict[str, list[tuple[str, str]]]:
        return {k: list(v.items()) for k, v in self._data.items() if v}
