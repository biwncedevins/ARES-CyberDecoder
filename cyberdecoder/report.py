"""Report generation: TXT / JSON / hexdump."""
from __future__ import annotations

import base64
from datetime import datetime

from . import APP_NAME, __version__
from . import interpret
from . import ioc as iocmod
from .engine import Analysis, decode_text

DISPLAY_LIMIT = 2_000_000       # chars shown in the GUI / written to the TXT report


def hexdump(data: bytes, limit: int = 4096) -> str:
    rows = []
    chunk = data[:limit]
    for off in range(0, len(chunk), 16):
        part = chunk[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in part).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in part)
        rows.append(f"{off:08x}  {hx}  {asc}")
    if len(data) > limit:
        rows.append(f"... (+{len(data) - limit} bytes)")
    return "\n".join(rows)


def display_text(data: bytes, limit: int = DISPLAY_LIMIT, binary: bool | None = None) -> str:
    """Text for viewers: decoded text, or a hexdump for binary data."""
    if not data:
        return ""
    text, _ = decode_text(data)
    if text is not None and binary is not True:
        text = text.replace("\x00", "\u2400")
        if len(text) > limit:
            return text[:limit] + f"\n\n… (تم اقتطاع العرض: {len(text)} حرف؛ التصدير يحتوي البيانات كاملة)"
        return text
    return hexdump(data)


def final_view(a: Analysis) -> str:
    return display_text(a.final, binary=(a.final_type == "Binary"))


def build_text_report(a: Analysis) -> str:
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    bar = "=" * 72
    out: list[str] = [
        bar,
        f" {APP_NAME} {__version__}  |  تقرير التحليل / Analysis Report",
        bar,
        f"Generated : {now}",
        f"Source    : {a.source}",
        f"Input     : {a.original_type} | {len(a.original)} bytes | SHA-256 {a.sha256_original}",
        f"Final     : {a.final_type} | {len(a.final)} bytes | SHA-256 {a.sha256_final}",
        "",
        "--- الملخص / Summary " + "-" * 48,
    ]
    out += [f"  {line}" for line in interpret.summarize(a)]

    out += ["", "--- الطبقات / Layers " + "-" * 49]
    if a.layers:
        for l in a.layers:
            detail = f" ({l.out_detail})" if l.out_detail else ""
            out.append(f"  [{l.index}] {l.method:<16} confidence {l.confidence:>3}%  ->  "
                       f"{l.out_type}{detail}, {l.out_size} bytes")
            for n in l.notes:
                out.append(f"        - {n}")
    else:
        out.append("  (لا توجد طبقات)")
    for h in a.hints:
        out.append(f"  * {h}")

    out += ["", "--- الملاحظات / Findings " + "-" * 45]
    if a.findings:
        for f in a.findings:
            ev = f"  ::  {f.evidence}" if f.evidence else ""
            out.append(f"  [{f.level.upper():<6}] {f.title}{ev}")
    else:
        out.append("  (لا توجد ملاحظات)")

    out += ["", "--- المؤشرات / IOCs " + "-" * 50]
    if a.iocs:
        for typ, items in a.iocs.items():
            out.append(f"  {iocmod.TYPE_LABELS[typ]} ({len(items)})")
            for value, src in items:
                out.append(f"    {value}    [{src}]")
    else:
        out.append("  (لا توجد مؤشرات)")

    if a.embedded:
        out += ["", "--- مقاطع مضمّنة / Embedded " + "-" * 42]
        for k, e in enumerate(a.embedded, 1):
            chain = " -> ".join(l.method for l in e.analysis.layers)
            prev = display_text(e.analysis.final, 200).replace("\n", " ")[:160]
            tok = e.token if len(e.token) <= 60 else e.token[:57] + "..."
            out.append(f"  #{k} @offset {e.offset}: {tok}")
            out.append(f"      {chain}  =>  {prev}")

    out += ["", "--- الناتج النهائي / Final Output " + "-" * 38, final_view(a), "", bar]
    return "\n".join(out)


def build_json_report(a: Analysis) -> dict:
    final_text, _ = decode_text(a.final)
    is_text = final_text is not None and a.final_type != "Binary"
    return {
        "tool": APP_NAME,
        "version": __version__,
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source": a.source,
        "input": {"type": a.original_type, "size": len(a.original), "sha256": a.sha256_original},
        "summary": interpret.summarize(a),
        "layers": [
            {
                "index": l.index, "method": l.method, "confidence": l.confidence,
                "output_type": l.out_type, "output_detail": l.out_detail,
                "input_size": l.in_size, "output_size": l.out_size, "notes": l.notes,
            }
            for l in a.layers
        ],
        "final": {
            "type": a.final_type, "detail": a.final_detail, "size": len(a.final), "sha256": a.sha256_final,
            "text": final_text if is_text else None,
            "base64": None if is_text else base64.b64encode(a.final[:1_000_000]).decode("ascii"),
        },
        "findings": [{"level": f.level, "title": f.title, "evidence": f.evidence} for f in a.findings],
        "iocs": {k: [{"value": v, "source": s} for v, s in items] for k, items in a.iocs.items()},
        "embedded": [
            {
                "offset": e.offset, "token": e.token,
                "layers": [l.method for l in e.analysis.layers],
                "final_type": e.analysis.final_type,
                "final_text": display_text(e.analysis.final, 5000),
            }
            for e in a.embedded
        ],
        "warnings": a.warnings,
        "hints": a.hints,
        "stop_reason": a.stop_reason,
        "elapsed_ms": round(a.elapsed_ms, 2),
    }
