#!/usr/bin/env python
"""
NO-SAST - single-file Android APK scanner that screenshots every finding.

    python nosast.py app.apk
    python nosast.py                  # prompts for the APK path

For each issue it finds, it renders a PNG of the exact code that is wrong,
with the offending line highlighted in red and every surrounding line kept
in place, and files it as:

    <AppName>/<Issue name>/<file>_L<line>.png

Checks implemented (manifest, signing and layout, all from the APK itself):

  001 outdated minSdkVersion              012 task hijacking (taskAffinity)
  002 targetSdkVersion not current        013 hardcoded secrets in meta-data
  003 backup data exposure                014 unprotected file provider
  004 debuggable release build            015 custom permission misuse
  005 cleartext traffic permitted         016 excessive exported activities
  006 exported activities                 017 implicit broadcast handling
  007 exported services                   018 unencrypted / unfiltered backup
  008 exported content providers          019 insecure intent / deep links
  009 insecure external storage perms     020 maxSdkVersion declared
  010 excessive permissions               021 tapjacking (no obscured-touch
  011 unprotected broadcast receivers         filter on any layout)
                                          022 missing signature scheme v3
                                          023 missing signature scheme v4
                                          024 v1-only signing / debug cert

Requires: python 3.8+ and Pillow (pip install pillow). Nothing else - the
binary AndroidManifest.xml and the APK signing block are parsed here.
"""

import argparse
import os
import re
import struct
import sys
import zipfile

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("[!] Pillow is required for the screenshots:\n    pip install pillow")
    sys.exit(1)


# ===========================================================================
#  SECTION 1 - binary XML (AXML) decoder
# ===========================================================================
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

TYPE_NULL, TYPE_REFERENCE, TYPE_ATTRIBUTE, TYPE_STRING = 0x00, 0x01, 0x02, 0x03
TYPE_FLOAT, TYPE_DIMENSION, TYPE_FRACTION = 0x04, 0x05, 0x06
TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN = 0x10, 0x11, 0x12

DIM_UNITS = ("px", "dip", "sp", "pt", "in", "mm")
FRAC_UNITS = ("%", "%p")
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AxmlError(Exception):
    pass


class StringPool:
    def __init__(self, data, off):
        ctype, header_size, _size = struct.unpack_from("<HHI", data, off)
        if ctype != RES_STRING_POOL:
            raise AxmlError("no string pool at 0x%x" % off)
        count, _styles, flags, strings_start, _ss = struct.unpack_from(
            "<IIIII", data, off + 8)
        self.utf8 = bool(flags & (1 << 8))
        self.strings = []
        if not count:
            return
        offsets = struct.unpack_from("<%dI" % count, data, off + header_size)
        base = off + strings_start
        for o in offsets:
            try:
                self.strings.append(self._read(data, base + o))
            except Exception:
                self.strings.append("")

    def _read(self, data, p):
        if self.utf8:
            _n, p = self._v8(data, p)          # utf16 length (unused)
            n, p = self._v8(data, p)           # byte length
            return data[p:p + n].decode("utf-8", "replace")
        n, p = self._v16(data, p)
        return data[p:p + n * 2].decode("utf-16-le", "replace")

    @staticmethod
    def _v8(data, p):
        v = data[p]
        p += 1
        if v & 0x80:
            v = ((v & 0x7F) << 8) | data[p]
            p += 1
        return v, p

    @staticmethod
    def _v16(data, p):
        v = struct.unpack_from("<H", data, p)[0]
        p += 2
        if v & 0x8000:
            lo = struct.unpack_from("<H", data, p)[0]
            p += 2
            v = ((v & 0x7FFF) << 16) | lo
        return v, p

    def get(self, i):
        if i is None or i < 0 or i >= len(self.strings):
            return None
        return self.strings[i]


class Node:
    """One element, annotated with the row it gets printed on."""

    __slots__ = ("tag", "attrs", "children", "parent", "line", "attr_lines",
                 "end_line")

    def __init__(self, tag, parent=None):
        self.tag = tag
        self.attrs = {}
        self.children = []
        self.parent = parent
        self.line = 0
        self.attr_lines = {}
        self.end_line = 0

    def a(self, name, default=None):
        """Attribute lookup; the android: prefix is optional."""
        if name in self.attrs:
            return self.attrs[name]
        return self.attrs.get("android:" + name, default)

    def line_of(self, name):
        """Row of one attribute, falling back to the element's own row."""
        for k in (name, "android:" + name):
            if k in self.attr_lines:
                return self.attr_lines[k]
        return self.line

    def find_all(self, tag):
        out = []
        for c in self.children:
            if c.tag == tag:
                out.append(c)
            out.extend(c.find_all(tag))
        return out

    def find(self, tag):
        r = self.find_all(tag)
        return r[0] if r else None

    def name(self):
        return self.a("name") or ""


class Axml:
    """Decoded binary XML plus the pretty text the screenshots show.

    The emitter writes one attribute per line on purpose: that is what lets a
    finding point at a single row, so the highlight marks the actual problem
    rather than a whole element.
    """

    def __init__(self, data):
        self.pool = None
        self.res_map = []
        self.ns = {}
        self.root = None
        self._parse(data)
        self.lines = []
        self._emit()
        self.text = "\n".join(self.lines)

    # -- chunk walk --------------------------------------------------------
    def _parse(self, data):
        if len(data) < 8:
            raise AxmlError("file too small")
        ctype, hsize, total = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_XML:
            raise AxmlError("not binary AXML (type=0x%x)" % ctype)
        off, stack, limit = hsize, [], min(total, len(data))
        while off < limit - 7:
            ctype, hsz, csz = struct.unpack_from("<HHI", data, off)
            if csz <= 0:
                break
            if ctype == RES_STRING_POOL:
                self.pool = StringPool(data, off)
            elif ctype == RES_XML_RESOURCE_MAP:
                n = (csz - hsz) // 4
                if n > 0:
                    self.res_map = list(
                        struct.unpack_from("<%dI" % n, data, off + hsz))
            elif ctype == RES_XML_START_NAMESPACE:
                pi, ui = struct.unpack_from("<ii", data, off + hsz)
                self.ns[self.pool.get(ui) or ""] = self.pool.get(pi) or ""
            elif ctype == RES_XML_START_ELEMENT:
                node = self._element(data, off, hsz,
                                     stack[-1] if stack else None)
                if stack:
                    stack[-1].children.append(node)
                elif self.root is None:
                    self.root = node
                stack.append(node)
            elif ctype == RES_XML_END_ELEMENT:
                if stack:
                    stack.pop()
            off += csz
        if self.root is None:
            raise AxmlError("no root element")

    def _element(self, data, off, hsz, parent):
        ns_i, name_i = struct.unpack_from("<ii", data, off + hsz)
        a_start, a_size, a_count = struct.unpack_from("<HHH", data, off + hsz + 8)
        node = Node(self.pool.get(name_i) or "?", parent)
        p = off + hsz + a_start
        for _ in range(a_count):
            a_ns, a_name, a_raw = struct.unpack_from("<iii", data, p)
            a_type = data[p + 15]
            a_data = struct.unpack_from("<i", data, p + 16)[0]
            nm = self.pool.get(a_name) or ""
            if not nm:
                nm = ("attr_0x%08x" % self.res_map[a_name]
                      if 0 <= a_name < len(self.res_map) else "attr_%d" % a_name)
            uri = self.pool.get(a_ns)
            if uri:
                prefix = self.ns.get(uri) or (
                    "android" if uri == ANDROID_NS else "ns")
                nm = "%s:%s" % (prefix, nm)
            node.attrs[nm] = self._value(a_type, a_data, a_raw)
            p += a_size
        return node

    def _value(self, t, d, raw):
        if t == TYPE_STRING:
            s = self.pool.get(raw)
            if s is None:
                s = self.pool.get(d)
            return s if s is not None else ""
        if t == TYPE_NULL:
            return ""
        if t == TYPE_INT_BOOLEAN:
            return "true" if d != 0 else "false"
        if t == TYPE_INT_DEC:
            return str(d)
        if t == TYPE_INT_HEX:
            return "0x%08x" % (d & 0xFFFFFFFF)
        if t == TYPE_REFERENCE:
            return "@0x%08x" % (d & 0xFFFFFFFF)
        if t == TYPE_ATTRIBUTE:
            return "?0x%08x" % (d & 0xFFFFFFFF)
        if t == TYPE_FLOAT:
            return "%g" % struct.unpack("<f", struct.pack("<i", d))[0]
        if t in (TYPE_DIMENSION, TYPE_FRACTION):
            units = DIM_UNITS if t == TYPE_DIMENSION else FRAC_UNITS
            m = d & 0xFFFFFF00
            if m & 0x80000000:
                m -= 0x100000000
            mult = 1.0 / (1 << (8, 15, 23, 31)[(d >> 4) & 3])
            u = d & 0xF
            return "%g%s" % (m * mult, units[u] if u < len(units) else "")
        if 0x1C <= t <= 0x1F:
            return "#%08x" % (d & 0xFFFFFFFF)
        return str(d)

    # -- pretty printer that records line numbers --------------------------
    def _emit(self):
        self.lines.append('<?xml version="1.0" encoding="utf-8"?>')
        self._emit_node(self.root, 0)

    def _w(self, s):
        self.lines.append(s)
        return len(self.lines)          # 1-based row just written

    def _emit_node(self, node, depth):
        pad = "    " * depth
        attrs = []
        if node is self.root:
            for uri, prefix in self.ns.items():
                attrs.append(("xmlns:%s" % (prefix or "ns"), uri))
        attrs.extend(node.attrs.items())
        close = ">" if node.children else " />"
        if not attrs:
            node.line = self._w("%s<%s%s" % (pad, node.tag, close))
        else:
            node.line = self._w("%s<%s" % (pad, node.tag))
            for i, (k, v) in enumerate(attrs):
                tail = close if i == len(attrs) - 1 else ""
                node.attr_lines[k] = self._w(
                    '%s    %s="%s"%s' % (pad, k, _esc(v), tail))
        node.end_line = len(self.lines)
        if node.children:
            for c in node.children:
                self._emit_node(c, depth + 1)
            node.end_line = self._w("%s</%s>" % (pad, node.tag))

    # -- manifest shortcuts ------------------------------------------------
    @property
    def package(self):
        return self.root.a("package") or "unknown.package"

    @property
    def application(self):
        return self.root.find("application")

    def uses_sdk(self):
        return self.root.find("uses-sdk")

    def components(self, tag):
        app = self.application
        return app.find_all(tag) if app else []

    def permissions(self):
        return [n for n in self.root.children
                if n.tag in ("uses-permission", "uses-permission-sdk-23")]

    def custom_permissions(self):
        return [n for n in self.root.children if n.tag == "permission"]


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ===========================================================================
#  SECTION 2 - APK container and signing block
# ===========================================================================
SIG_MAGIC = b"APK Sig Block 42"
ID_V2, ID_V3, ID_V31 = 0x7109871A, 0xF05368C0, 0x1B93AD61
ID_STAMP1, ID_STAMP2 = 0x2B09189E, 0x6DFF800D

BLOCK_NAMES = {
    ID_V2: "APK Signature Scheme v2", ID_V3: "APK Signature Scheme v3",
    ID_V31: "APK Signature Scheme v3.1", ID_STAMP1: "SourceStamp v1",
    ID_STAMP2: "SourceStamp v2", 0x42726577: "verity padding",
    0x504B4453: "dependency info",
}

V1_SF = re.compile(r"^META-INF/[^/]+\.SF$", re.I)
V1_CERT = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", re.I)

# X.509 distinguished-name attribute OIDs, as they appear DER-encoded.
# Pulling these out of the certificate avoids needing keytool/apksigner.
DN_OIDS = [
    (b"\x06\x03\x55\x04\x03", "CN", "common name"),
    (b"\x06\x03\x55\x04\x0a", "O", "organisation"),
    (b"\x06\x03\x55\x04\x0b", "OU", "organisational unit"),
    (b"\x06\x03\x55\x04\x07", "L", "locality"),
    (b"\x06\x03\x55\x04\x08", "ST", "state"),
    (b"\x06\x03\x55\x04\x06", "C", "country"),
]
DER_STRING_TAGS = (0x13, 0x0C, 0x16, 0x14, 0x1E)

# every Android SDK generates ~/.android/debug.keystore with this subject
DEBUG_DN = {"CN": "android debug", "O": "android", "C": "us"}


def parse_dn(blob):
    """Distinguished-name attributes found in a DER certificate blob.

    Not a full ASN.1 parse - it locates each attribute OID and reads the
    directory string that follows it, which is all that is needed to tell a
    release certificate from the SDK debug certificate.
    """
    out = {}
    for oid, short, _label in DN_OIDS:
        at = 0
        while True:
            i = blob.find(oid, at)
            if i < 0:
                break
            p = i + len(oid)
            if p + 1 < len(blob) and blob[p] in DER_STRING_TAGS:
                ln = blob[p + 1]
                if ln < 0x80 and p + 2 + ln <= len(blob):
                    raw = blob[p + 2:p + 2 + ln]
                    try:
                        v = raw.decode("utf-8" if blob[p] == 0x0C else "latin-1")
                    except (UnicodeDecodeError, ValueError):
                        v = ""
                    v = v.strip()
                    if v and v.isprintable():
                        vals = out.setdefault(short, [])
                        if v not in vals:
                            vals.append(v)
            at = i + 1
    return out


class Apk:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.zf = zipfile.ZipFile(self.path, "r")
        self.names = self.zf.namelist()
        self.size = os.path.getsize(self.path)
        with open(self.path, "rb") as fh:
            self.raw = fh.read()
        self.sig = self._signatures()

    def read(self, name):
        try:
            return self.zf.read(name)
        except KeyError:
            return None

    def manifest(self):
        data = self.read("AndroidManifest.xml")
        if data is None:
            raise AxmlError("AndroidManifest.xml is missing from the APK")
        return Axml(data)

    def dex_files(self):
        return sorted(n for n in self.names
                      if n.startswith("classes") and n.endswith(".dex"))

    def dex_strings(self, min_len=12):
        """Every printable literal in the DEX string tables.

        String constants are stored in the clear even after R8, so SQL
        statements, URLs and format strings are recoverable from a release
        APK without decompiling anything.
        """
        out = []
        for name in self.dex_files():
            data = self.read(name) or b""
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
                out.append((name, m.group(0).decode("ascii", "ignore")))
        return out

    def dex_contains(self, needle):
        """Count occurrences of an ASCII symbol across every DEX.

        Method names survive into the DEX string table even under R8, so
        searching the raw bytes tells us whether the app calls an API -
        without needing a decompiler.
        """
        token = needle.encode("ascii")
        hits = []
        for name in self.dex_files():
            data = self.read(name) or b""
            n = data.count(token)
            if n:
                hits.append((name, n))
        return hits

    def res_xml(self):
        """Every binary XML resource.

        Release builds shorten resource paths (res/0C.xml), so a layout can
        not be recognised by its name - the tapjacking check classifies each
        file by the tags inside it instead.
        """
        return [n for n in self.names
                if n.startswith("res/") and n.endswith(".xml")]

    # -- signing block -----------------------------------------------------
    def _cd_offset(self):
        tail = self.raw[-min(len(self.raw), 65557):]
        i = tail.rfind(b"PK\x05\x06")
        if i < 0:
            return None
        base = len(self.raw) - len(tail) + i
        off = struct.unpack_from("<I", self.raw, base + 16)[0]
        if off == 0xFFFFFFFF:
            z = self.raw.rfind(b"PK\x06\x06")
            if z < 0:
                return None
            off = struct.unpack_from("<Q", self.raw, z + 48)[0]
        return off

    def signing_block(self):
        raw, cd = self.raw, self._cd_offset()
        if cd is None or cd < 32 or raw[cd - 16:cd] != SIG_MAGIC:
            return {}
        size = struct.unpack_from("<Q", raw, cd - 24)[0]
        start = cd - size - 8
        if start < 0 or struct.unpack_from("<Q", raw, start)[0] != size:
            return {}
        out, p = {}, start + 8
        while p < cd - 24:
            ln = struct.unpack_from("<Q", raw, p)[0]
            if ln < 4 or p + 8 + ln > cd:
                break
            out[struct.unpack_from("<I", raw, p + 8)[0]] = ln - 4
            p += 8 + ln
        return out

    def signing_block_bytes(self):
        """Raw bytes of the APK Signing Block, which carry the v2/v3 certs."""
        raw, cd = self.raw, self._cd_offset()
        if cd is None or cd < 32 or raw[cd - 16:cd] != SIG_MAGIC:
            return b""
        size = struct.unpack_from("<Q", raw, cd - 24)[0]
        start = cd - size - 8
        if start < 0:
            return b""
        return raw[start:cd - 24]

    def _signatures(self):
        blk = self.signing_block()
        sf = [n for n in self.names if V1_SF.match(n)]
        crt = [n for n in self.names if V1_CERT.match(n)]
        idsig = self.path + ".idsig"
        info = {
            "v1": bool(sf and crt), "v2": ID_V2 in blk, "v3": ID_V3 in blk,
            "v3.1": ID_V31 in blk, "v4": os.path.isfile(idsig),
            "stamp": (ID_STAMP1 in blk) or (ID_STAMP2 in blk),
            "block": blk, "debug_cert": False, "dn": {}, "dn_from": "",
        }
        info["present"] = [k for k in ("v1", "v2", "v3", "v3.1", "v4")
                           if info[k]]
        info["missing"] = [k for k in ("v1", "v2", "v3", "v3.1", "v4")
                           if not info[k]]

        # read the certificate subject from wherever it lives: the v1 PKCS#7
        # blob, or the v2/v3 signing block when the APK has no v1 signature
        sources = []
        if crt:
            sources.append((crt[0], self.read(crt[0]) or b""))
        sources.append(("APK signing block", self.signing_block_bytes()))
        for where, blob in sources:
            if not blob:
                continue
            dn = parse_dn(blob)
            if dn:
                info["dn"] = dn
                info["dn_from"] = where
                break

        dn = info["dn"]
        lowered = {k: [v.lower() for v in vals] for k, vals in dn.items()}
        info["debug_cert"] = any(
            DEBUG_DN[k] in lowered.get(k, []) for k in ("CN",)) or all(
            DEBUG_DN[k] in lowered.get(k, []) for k in DEBUG_DN)
        return info

    def signing_report(self):
        """Readable summary; each signing finding highlights a row of this.

        Returns (rows, index) where index maps a key to the 1-based row the
        corresponding finding should box in red.
        """
        s = self.sig
        rows, idx = [], {}

        def add(line, key=None):
            rows.append(line)
            if key:
                idx[key] = len(rows)

        add("APK signing block summary")
        add("")
        add("file                  : %s" % os.path.basename(self.path))
        add("size                  : %d bytes" % self.size)
        add("has APK signing block : %s" % ("yes" if s["block"] else "no"))
        add("scheme v1 (JAR)       : %s"
            % ("present" if s["v1"] else "ABSENT"), "v1")
        add("scheme v2  0x7109871a : %s"
            % ("present" if s["v2"] else "ABSENT"), "v2")
        add("scheme v3  0xf05368c0 : %s"
            % ("present" if s["v3"] else "ABSENT"), "v3")
        add("scheme v3.1 0x1b93ad61: %s"
            % ("present" if s["v3.1"] else "ABSENT"), "v3.1")
        add("scheme v4  <apk>.idsig: %s"
            % ("present" if s["v4"] else "ABSENT"), "v4")
        add("source stamp          : %s"
            % ("present" if s["stamp"] else "absent"))
        add("")

        dn = s["dn"]
        add("signing certificate   : %s" % (s["dn_from"] or "not recovered"))
        if dn:
            for _oid, short, label in DN_OIDS:
                for v in dn.get(short, [])[:2]:
                    flag = ""
                    if short in DEBUG_DN and v.lower() == DEBUG_DN[short]:
                        flag = "   <-- Android SDK debug certificate"
                    add("    %-2s (%-19s): %s%s" % (short, label, v, flag),
                        "dn_" + short if flag else None)
        else:
            add("    (no distinguished name could be read)")
        add("    verdict           : %s"
            % ("ANDROID DEBUG CERTIFICATE - the private key is public"
               if s["debug_cert"] else "not the SDK debug certificate"),
            "debug")
        add("")

        add("signing block contents:")
        if not s["block"]:
            add("    (none - this is a v1-only archive)")
        for pid, ln in sorted(s["block"].items()):
            add("    0x%08x  %-28s %d bytes"
                % (pid, BLOCK_NAMES.get(pid, "unknown"), ln))
        return rows, idx


SIG_FILE = "apk-signing-block.txt"
TAPJACK_FILE = "tapjacking-check.txt"
SQL_FILE = "sql-queries-recovered.txt"
MANIFEST = "AndroidManifest.xml"

# a literal that reaches the DEX looking like one of these was built by
# concatenation at runtime - the value that completes it is not in the APK
SQL_STMT = re.compile(
    r"\b(SELECT\s+|INSERT\s+(OR\s+\w+\s+)?INTO\s+|UPDATE\s+\w+\s+SET\s+|"
    r"DELETE\s+FROM\s+|CREATE\s+(UNIQUE\s+)?(TABLE|INDEX|VIEW|TRIGGER)\s+|"
    r"DROP\s+(TABLE|INDEX|VIEW)\s+|ALTER\s+TABLE\s+|REPLACE\s+INTO\s+)",
    re.I)

SQL_CONCAT = re.compile(
    r"("
    r"(=|<|>|<=|>=|<>|!=|\bLIKE\b|\bIN\b|\bVALUES\b)\s*\(?\s*'?\s*$"   # cut off
    r"|%[sd]"                                                          # format
    r"|\|\|\s*$"
    r"|\bWHERE\b[^?]*$"                                                # no bind
    r")", re.I)


# ===========================================================================
#  SECTION 3 - findings model
# ===========================================================================
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Ev:
    """A code window plus the row(s) that get the red highlight."""

    def __init__(self, file, focus, start=None, end=None, note=""):
        if isinstance(focus, int):
            focus = [focus]
        self.file = file
        self.focus = sorted({int(f) for f in focus if f})
        self.note = note
        lo = min(self.focus) if self.focus else 1
        hi = max(self.focus) if self.focus else 1
        self.start = int(start) if start else max(1, lo - 7)
        self.end = int(end) if end else hi + 7


class Finding:
    def __init__(self, fid, title, severity, why, fix, cwe=""):
        self.id = fid
        self.title = title
        self.severity = severity
        self.why = why          # one line shown under the code
        self.fix = fix
        self.cwe = cwe
        self.ev = []

    def add(self, ev):
        self.ev.append(ev)
        return self

    @property
    def rank(self):
        return SEV_ORDER.get(self.severity, 9)

    def dirname(self):
        return re.sub(r"[^A-Za-z0-9]+", "_", self.title).strip("_")[:70]


class Secure(Finding):
    """A control that is correctly configured, filed under Secured/."""

    def __init__(self, title, what, cwe=""):
        Finding.__init__(self, "SECURE", title, "SECURE", what, "", cwe)


# ===========================================================================
#  SECTION 4 - rules
# ===========================================================================
LATEST_SDK = 36
SAFE_MINSDK = 28
SAFE_TARGET = 33

DANGEROUS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.BODY_SENSORS", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS", "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
}

SPECIAL = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_LOGS", "android.permission.INSTALL_PACKAGES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
}

STORAGE = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_MEDIA",
}

SENSITIVE_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER",
    "android.intent.action.USER_PRESENT", "android.intent.action.SCREEN_ON",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "com.google.android.c2dm.intent.RECEIVE",
}

SECRET_NAME = re.compile(
    r"(api[_\-.]?key|apikey|secret|passwd|password|client[_\-.]?secret|"
    r"private[_\-.]?key|auth[_\-.]?token|access[_\-.]?token|bearer|"
    r"credential|licen[cs]e[_\-.]?key|encrypt(ion)?[_\-.]?key|"
    r"signing[_\-.]?key|otp[_\-.]?key)", re.I)

SECRET_VALUE = re.compile(
    r"(AIza[0-9A-Za-z_\-]{30,}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{10,}|"
    r"ghp_[0-9A-Za-z]{30,}|xox[baprs]-[0-9A-Za-z\-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,})")

PROT_BASE = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}
PROT_FLAGS = [(0x10, "privileged"), (0x20, "development"), (0x40, "appop"),
              (0x80, "pre23"), (0x100, "installer"), (0x200, "verifier"),
              (0x400, "preinstalled"), (0x800, "setup"), (0x1000, "instant"),
              (0x2000, "runtime"), (0x4000, "oem"),
              (0x8000, "vendorPrivileged"), (0x8000000, "knownSigner")]


def prot_level(raw):
    """protectionLevel comes out of the binary manifest as an int bitmask."""
    if raw is None:
        return "normal"
    s = str(raw).strip()
    if not s:
        return "normal"
    if not (s.isdigit() or s.startswith("0x")):
        return s.lower()
    try:
        v = int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return s.lower()
    parts = [PROT_BASE.get(v & 0xF, "normal")]
    parts += [n for bit, n in PROT_FLAGS if v & bit]
    return "|".join(parts)


def _int(v, d=0):
    try:
        return int(str(v), 16) if str(v).startswith("0x") else int(v)
    except (TypeError, ValueError):
        return d


def _true(v):
    return str(v).lower() == "true"


class Scan:
    """Holds the decoded APK and runs every rule against it."""

    def __init__(self, apk):
        self.apk = apk
        self.mf = apk.manifest()
        self.sig = apk.sig
        mf = self.mf
        u = mf.uses_sdk()
        self.u = u
        self.min_sdk = _int(u.a("minSdkVersion") if u else None, 0)
        self.target_sdk = _int(u.a("targetSdkVersion") if u else None,
                               self.min_sdk)
        self.max_sdk = u.a("maxSdkVersion") if u else None
        self.app = mf.application
        self.custom = {p.name(): prot_level(p.a("protectionLevel"))
                       for p in mf.custom_permissions()}
        self.perms = {p.name(): p for p in mf.permissions() if p.name()}
        sig_rows, self.sig_idx = apk.signing_report()
        self.sources = {MANIFEST: mf.lines, SIG_FILE: sig_rows}
        self.secure = []            # controls that are correctly configured
        self.layout_guards = []     # (file, line) of filterTouchesWhenObscured
        self._scan_layouts()
        self._scan_tapjack()
        self._scan_sql()

    # -- layout pass: does ANY view filter obscured touches? ---------------
    VIEW_TAG = re.compile(
        r"(Layout|View|Button|TextView|EditText|Image|ViewGroup|Spinner|"
        r"CheckBox|Switch|RadioGroup|Toolbar|WebView|^merge$|^include$|"
        r"^fragment$|Picker|SeekBar|Slider|Chip|Card|Recycler|Pager)")
    INPUT_TAG = re.compile(r"(EditText|Button|CheckBox|Switch|RadioButton|"
                           r"Spinner|Chip|Slider|SeekBar)")

    def _scan_layouts(self):
        self.layout_files = []     # (name, doc, has_input)
        for name in self.apk.res_xml():
            data = self.apk.read(name)
            if not data or len(data) < 8 or data[0:2] != b"\x03\x00":
                continue
            try:
                doc = Axml(data)
            except Exception:
                continue
            nodes = self._walk(doc.root)
            tags = [n.tag for n in nodes]
            if not any(self.VIEW_TAG.search(t) for t in tags):
                continue           # not a layout (drawable, prefs, paths, ...)
            self.sources[name] = doc.lines
            self.layout_files.append(
                (name, doc, any(self.INPUT_TAG.search(t) for t in tags)))
            for n in nodes:
                for k, v in n.attrs.items():
                    if "filterTouchesWhenObscured" in k and _true(v):
                        self.layout_guards.append((name, n.line_of(k)))

    @staticmethod
    def _walk(node):
        out = [node]
        for c in node.children:
            out.extend(Scan._walk(c))
        return out

    # -- tapjacking: look for BOTH controls, XML and code -------------------
    def _scan_tapjack(self):
        """android:filterTouchesWhenObscured and setFilterTouchesWhenObscured.

        The first is a layout attribute, found by decoding every resource.
        The second is a runtime call, found by searching the DEX string
        tables - method names survive R8, so this is reliable without a
        decompiler. If either one exists anywhere, the app has the control
        and nothing is reported.
        """
        self.dex_guards = self.apk.dex_contains("setFilterTouchesWhenObscured")
        self.dex_attr = self.apk.dex_contains("filterTouchesWhenObscured")
        xml_n = len(self.layout_guards)
        dex_n = sum(c for _f, c in self.dex_guards)

        rows = [
            "Tapjacking control check",
            "",
            "search 1 - android:filterTouchesWhenObscured  (layout resources)",
            "    layout resources decoded : %d" % len(self.layout_files),
            "    layouts with the attribute: %-4d %s"
            % (xml_n, "" if xml_n else "<-- NOT FOUND"),
            "",
            "search 2 - setFilterTouchesWhenObscured(true)  (compiled code)",
            "    dex files searched       : %d" % len(self.apk.dex_files()),
            "    call sites found         : %-4d %s"
            % (dex_n, "" if dex_n else "<-- NOT FOUND"),
            "",
        ]
        if xml_n or dex_n:
            rows.append("result: the app does filter obscured touches")
        else:
            rows.append("result: NEITHER control exists anywhere in this APK,")
            rows.append("        so no window rejects taps delivered through")
            rows.append("        an overlay")
        self.sources[TAPJACK_FILE] = rows
        self.tapjack_rows = {"xml": 5, "dex": 9, "result": 11}
        self.tapjack_ok = bool(xml_n or dex_n)

    # -- SQL recovered straight out of the DEX string tables ---------------
    def _scan_sql(self):
        seen, stmts = set(), []
        for _dex, text in self.apk.dex_strings(14):
            t = text.strip()
            if len(t) > 400:
                t = t[:400] + " ..."
            m = SQL_STMT.search(t)
            if not m:
                continue
            # printable runs in the dex pick up neighbouring bytes - start
            # the statement at the keyword that identified it
            t = t[m.start():].strip()
            # drop obvious non-SQL that merely contains the keyword
            if t.lower().startswith(("http", "content://", "android.")):
                continue
            key = t.lower()
            if key in seen:
                continue
            seen.add(key)
            stmts.append(t)
        stmts.sort(key=lambda s: (not bool(SQL_CONCAT.search(s)), s.lower()))

        self.sql_risky = []
        rows = [
            "SQL statements recovered from the compiled application",
            "",
            "source  : %s" % ", ".join(self.apk.dex_files()),
            "found   : %d distinct statement(s)" % len(stmts),
            "marked  : the statement is cut off mid-expression or carries a "
            "format",
            "          placeholder, so a value is concatenated into it at "
            "runtime",
            "",
        ]
        head = len(rows)
        for i, t in enumerate(stmts, 1):
            rows.append("[%03d] %s" % (i, t))
            if SQL_CONCAT.search(t):
                self.sql_risky.append(head + i)
        if not stmts:
            rows.append("      (no SQL literals in the dex string tables)")
        self.sources[SQL_FILE] = rows
        self.sql_rows = rows
        self.sql_count = len(stmts)
        self.sql_head = head

    # -- secure findings ---------------------------------------------------
    def ok(self, title, what, ev, cwe=""):
        s = Secure(title, what, cwe)
        for e in (ev if isinstance(ev, list) else [ev]):
            s.add(e)
        if s.ev:
            self.secure.append(s)
        return s

    # -- exposure model ----------------------------------------------------
    def exported(self, n):
        e = n.a("exported")
        if e is not None:
            return _true(e)
        if n.tag == "provider":
            return self.target_sdk < 17
        return bool(n.find("intent-filter"))

    def why_exported(self, n):
        e = n.a("exported")
        if e is not None:
            return 'android:exported="%s" is declared' % e
        if n.tag == "provider":
            return ("android:exported is absent and targetSdk=%d < 17, so it "
                    "defaults to exported" % self.target_sdk)
        return ("android:exported is absent but an <intent-filter> is "
                "declared, so the platform treats it as exported")

    def guard(self, n):
        p = (n.a("permission") or n.a("readPermission")
             or n.a("writePermission"))
        if not p:
            return None, "none"
        lvl = self.custom.get(p)
        if lvl is None:
            lvl = "platform" if p.startswith("android.permission.") else "unknown"
        return p, lvl

    def unguarded(self, n):
        p, lvl = self.guard(n)
        if p is None:
            return True, "no android:permission guard"
        if "signature" in lvl:
            return False, ""
        return True, "guarded only by %s (protectionLevel=%s), which any app " \
                     "can request" % (p, lvl)

    # -- evidence helper ---------------------------------------------------
    def ev(self, node, attr=None, note=""):
        focus = node.line_of(attr) if attr else node.line
        start, end = max(1, node.line - 1), min(node.end_line + 1,
                                                len(self.mf.lines))
        if end - start > 44:
            start, end = max(1, focus - 7), focus + 7
        return Ev(MANIFEST, focus, start, end, note)

    def group(self, pairs, note):
        """One image covering several rows, every one of them highlighted.

        Used where listing each hit separately would mean a folder full of
        near-identical screenshots - the permission block, for instance,
        reads better as a single window with each flagged row boxed.
        """
        rows = sorted({n.line_of(attr) for n, attr in pairs})
        return Ev(MANIFEST, rows, max(1, rows[0] - 2),
                  min(rows[-1] + 2, len(self.mf.lines)), note)

    def sev(self, key, note):
        rows = self.sources[SIG_FILE]
        return Ev(SIG_FILE, self.sig_idx.get(key, 1), 1, len(rows), note)

    # =====================================================================
    def run(self):
        out = []
        for fn in (self.r001, self.r002, self.r003, self.r004, self.r005,
                   self.r006, self.r007, self.r008, self.r009, self.r010,
                   self.r011, self.r012, self.r013, self.r014, self.r015,
                   self.r016, self.r017, self.r018, self.r019, self.r020,
                   self.r021, self.r022, self.r023, self.r024, self.r025, self.r026):
            try:
                f = fn()
            except Exception as e:
                print("    [!] %s failed: %s" % (fn.__name__, e))
                continue
            if f and f.ev:
                out.append(f)
        out.sort(key=lambda f: (f.rank, f.id))
        return out

    # ---- 001 -------------------------------------------------------------
    def r001(self):
        if not self.min_sdk or self.min_sdk >= SAFE_MINSDK:
            return None
        f = Finding(
            "NOSAST-001", "Insecure Minimum SDK",
            "HIGH" if self.min_sdk < 21 else "MEDIUM",
            "minSdkVersion=%d lets the app install on Android releases that no "
            "longer get security fixes. Below API 23 every requested "
            "permission is granted at install time; below API 24 there is no "
            "per-app Network Security Config; below API 26 the platform is "
            "vulnerable to the Janus signature bug." % self.min_sdk,
            "Raise minSdkVersion to %d or higher in app/build.gradle."
            % SAFE_MINSDK, "CWE-1104")
        return f.add(self.ev(self.u, "minSdkVersion",
                             "minSdkVersion=%d is below the hardened floor "
                             "of %d" % (self.min_sdk, SAFE_MINSDK)))

    # ---- 002 -------------------------------------------------------------
    def r002(self):
        if not self.target_sdk or self.target_sdk >= SAFE_TARGET:
            return None
        lost = []
        if self.target_sdk < 28:
            lost.append("cleartext HTTP is allowed by default")
            lost.append("task-affinity hijacking is not mitigated")
        if self.target_sdk < 30:
            lost.append("scoped storage is not enforced")
        if self.target_sdk < 31:
            lost.append("android:exported need not be declared and "
                        "PendingIntents are mutable by default")
        f = Finding(
            "NOSAST-002", "Not Targeting The Latest targetSdkVersion",
            "HIGH" if self.target_sdk < 28 else "MEDIUM",
            "targetSdkVersion=%d. Platform behaviour changes apply only to "
            "apps that target the API level introducing them, so this app "
            "opts out of everything shipped since: %s."
            % (self.target_sdk, "; ".join(lost)),
            "Target the latest stable SDK (%d) and re-test." % LATEST_SDK,
            "CWE-1104")
        return f.add(self.ev(self.u, "targetSdkVersion",
                             "targetSdkVersion=%d, current stable is %d"
                             % (self.target_sdk, LATEST_SDK)))

    # ---- 003 -------------------------------------------------------------
    def r003(self):
        app = self.app
        if app is None:
            return None
        v = app.a("allowBackup")
        if not (_true(v) or (v is None and self.min_sdk < 31)):
            if v is not None:
                self.ok("Backup Disabled",
                        "The app opts out of the Android backup set, so its "
                        "private data directory is not copied into adb "
                        "backups, cloud auto-backup or device transfers.",
                        self.ev(app, "allowBackup",
                                'android:allowBackup="false"'), "CWE-530")
            return None
        f = Finding(
            "NOSAST-003", "Backup Data Exposure (allowBackup)", "HIGH",
            "App data is included in the Android backup set, so anyone with "
            "the unlocked handset can run `adb backup -noapk %s` and walk "
            "away with the whole private data directory - shared_prefs, "
            "databases, cached tokens - with no root and no exploit."
            % self.mf.package,
            'Set android:allowBackup="false", or keep backup and exclude '
            "every credential store with android:dataExtractionRules and "
            "android:fullBackupContent.", "CWE-530")
        return f.add(self.ev(
            app, "allowBackup" if v is not None else None,
            'android:allowBackup="true"' if _true(v) else
            "android:allowBackup is not declared, so it defaults to true"))

    # ---- 004 -------------------------------------------------------------
    def r004(self):
        app = self.app
        if app is None or not _true(app.a("debuggable")):
            if app is not None and app.a("debuggable") is not None:
                self.ok("Debugging Disabled",
                        "The release build is not debuggable, so a local "
                        "process cannot attach a debugger or use run-as to "
                        "read the private data directory.",
                        self.ev(app, "debuggable",
                                'android:debuggable="false"'), "CWE-489")
            return None
        f = Finding(
            "NOSAST-004", "Debuggable Mode Enabled", "CRITICAL",
            "The release APK ships debuggable. Any local process can attach "
            "jdb, call arbitrary methods in the app's context, read its "
            "private directory via run-as and dump memory - no root needed. "
            "This removes the process boundary every other control relies on.",
            "Remove android:debuggable and let the release buildType manage "
            "it.", "CWE-489")
        return f.add(self.ev(app, "debuggable",
                             'android:debuggable="true" in a release build'))

    # ---- 005 -------------------------------------------------------------
    def r005(self):
        app = self.app
        if app is None:
            return None
        v = app.a("usesCleartextTraffic")
        nsc = app.a("networkSecurityConfig")
        if not (_true(v) or (v is None and self.target_sdk < 28 and nsc is None)):
            if v is not None and not _true(v):
                self.ok("Cleartext Traffic Blocked",
                        "The app refuses unencrypted HTTP, so traffic cannot "
                        "silently fall back off TLS.",
                        self.ev(app, "usesCleartextTraffic",
                                'android:usesCleartextTraffic="false"'),
                        "CWE-319")
            if nsc:
                self.ok("Network Security Config Declared",
                        "A per-app Network Security Config is in place, which "
                        "is where cleartext policy, trust anchors and "
                        "certificate pins are enforced.",
                        self.ev(app, "networkSecurityConfig",
                                "android:networkSecurityConfig is declared"),
                        "CWE-295")
            return None
        f = Finding(
            "NOSAST-005", "Cleartext Traffic Permitted", "HIGH",
            "The app may open unencrypted HTTP connections. Anyone on the "
            "network path - rogue Wi-Fi, hostile hotspot, a local VPN app - "
            "reads and rewrites that traffic, so session tokens and request "
            "bodies cross the wire in the clear and injected responses are "
            "trusted.",
            'Set android:usesCleartextTraffic="false" and ship a Network '
            "Security Config with cleartextTrafficPermitted=\"false\" plus a "
            "pin-set.", "CWE-319")
        return f.add(self.ev(
            app, "usesCleartextTraffic" if v is not None else None,
            'android:usesCleartextTraffic="true" permits plain HTTP'
            if _true(v) else
            "neither usesCleartextTraffic nor networkSecurityConfig is set "
            "and targetSdk=%d < 28, so cleartext is the default"
            % self.target_sdk))

    # ---- 006 / 007 -------------------------------------------------------
    def _exported_rule(self, tag, fid, title, sev, why, fix, cwe, label):
        hits = []
        for n in self.mf.components(tag):
            if not self.exported(n):
                continue
            weak, reason = self.unguarded(n)
            if weak:
                hits.append((n, reason))
        if not hits:
            return None
        f = Finding(fid, title, sev, why, fix, cwe)
        for n, reason in hits[:30]:
            f.add(self.ev(n, "exported", "%s %s - %s; %s"
                          % (label, n.name() or "(unnamed)",
                             self.why_exported(n), reason)))
        return f

    def r006(self):
        return self._exported_rule(
            "activity", "NOSAST-006", "Exported Activities", "HIGH",
            "These activities can be started by any other app with a crafted "
            "Intent. Anything behind them - a logged-in screen, a PIN entry, "
            "a WebView rendering an attacker URL, a transaction confirmation "
            "- is reachable without passing through the app's own navigation, "
            "so the auth and state checks the normal flow performs are "
            "skipped, and every Intent extra is attacker-controlled.",
            'Set android:exported="false" on everything that is not a '
            "deliberate entry point; guard the rest with a signature-level "
            "permission and validate the caller and all extras.",
            "CWE-926", "activity")

    def r007(self):
        return self._exported_rule(
            "service", "NOSAST-007", "Exported Services", "HIGH",
            "Any installed app can start or bind to these services. Exported "
            "services usually front privileged work - token refresh, key "
            "operations, database writes - and an unauthenticated bind lets a "
            "hostile app drive it with its own parameters. A bound AIDL "
            "interface hands the caller every method, not just the one the UI "
            "uses.",
            'Set android:exported="false" for internal services; require a '
            "signature-level permission and verify Binder.getCallingUid() "
            "where a service must stay reachable.", "CWE-926", "service")

    # ---- 008 -------------------------------------------------------------
    def r008(self):
        hits = []
        for n in self.mf.components("provider"):
            if not self.exported(n):
                continue
            weak, reason = self.unguarded(n)
            if weak:
                hits.append((n, reason))
        if not hits:
            return None
        f = Finding(
            "NOSAST-008", "Exported Content Providers", "CRITICAL",
            "An exported provider is a direct read/write channel into private "
            "storage, reachable with one `content query` from any app. "
            "Depending on its backing store that exposes the SQLite database "
            "including auth tables, arbitrary files under the data directory "
            "via openFile, or - if the selection argument is concatenated "
            "into SQL - full SQL injection against the app's own database.",
            'Set android:exported="false" and hand out per-item access with '
            "FLAG_GRANT_READ_URI_PERMISSION; declare signature-level "
            "readPermission/writePermission and parameterise every query.",
            "CWE-926")
        for n, reason in hits[:30]:
            attr = "exported" if n.a("exported") is not None else "authorities"
            f.add(self.ev(n, attr, "provider %s (authorities=%s) - %s; %s"
                          % (n.name() or "?", n.a("authorities") or "?",
                             self.why_exported(n), reason)))
        return f

    # ---- 009 -------------------------------------------------------------
    def r009(self):
        hits = [p for nm, p in self.perms.items() if nm in STORAGE]
        if not hits:
            return None
        manage = "android.permission.MANAGE_EXTERNAL_STORAGE" in self.perms
        f = Finding(
            "NOSAST-009", "Insecure External Storage Permissions",
            "HIGH" if manage else "MEDIUM",
            "External storage has no per-app access control: anything written "
            "there is readable by every other app holding the same "
            "permission, survives uninstall, and is reachable over MTP from a "
            "connected computer. Files read back from it are equally "
            "attacker-writable, so they must never be trusted as input."
            + (" MANAGE_EXTERNAL_STORAGE grants all-files access." if manage
               else ""),
            "Keep sensitive data in the private directory (getFilesDir, "
            "EncryptedFile); use MediaStore or the Storage Access Framework "
            "for user-visible files and drop MANAGE_EXTERNAL_STORAGE.",
            "CWE-276")
        return f.add(self.group([(p, "name") for p in hits],
                               "%d external-storage permission(s) requested: %s"
                               % (len(hits), ", ".join(
                                   p.name().split(".")[-1] for p in hits))))

    # ---- 010 -------------------------------------------------------------
    def r010(self):
        dang = sorted(set(self.perms) & DANGEROUS)
        spec = sorted(set(self.perms) & SPECIAL)
        if not dang and not spec and len(self.perms) < 25:
            return None
        f = Finding(
            "NOSAST-010", "Excessive Permissions",
            "HIGH" if spec else ("MEDIUM" if len(dang) >= 4 else "LOW"),
            "The app declares %d permissions - %d runtime-dangerous, %d "
            "special. Each widens what a compromise of this app or any "
            "library inside it can reach, and several are directly abusable: "
            "SYSTEM_ALERT_WINDOW enables overlay attacks, "
            "REQUEST_INSTALL_PACKAGES enables dropper behaviour, "
            "QUERY_ALL_PACKAGES fingerprints the device, "
            "BIND_ACCESSIBILITY_SERVICE can read and drive every other app."
            % (len(self.perms), len(dang), len(spec)),
            "Remove every permission the current feature set does not need "
            "and prefer narrower alternatives (Photo Picker, coarse "
            "location, <queries> instead of QUERY_ALL_PACKAGES).", "CWE-250")
        picked = spec + dang
        return f.add(self.group(
            [(self.perms[nm], "name") for nm in picked],
            "%d flagged permission(s) highlighted - %d special / "
            "high-privilege, %d runtime-dangerous"
            % (len(picked), len(spec), len(dang))))

    # ---- 011 -------------------------------------------------------------
    def r011(self):
        hits = []
        for n in self.mf.components("receiver"):
            if not self.exported(n):
                continue
            weak, reason = self.unguarded(n)
            if weak:
                hits.append((n, reason))
        if not hits:
            return None
        f = Finding(
            "NOSAST-011", "Unprotected Broadcast Receivers", "HIGH",
            "These receivers accept broadcasts from any app. A hostile app "
            "can forge whatever the receiver expects - a push payload, a "
            "'sync now' trigger, a logout or wipe command - and onReceive has "
            "no way to tell a forged Intent from a genuine one unless it "
            "checks.",
            'Set android:exported="false" and use an in-process flow for '
            "internal broadcasts; receivers that must accept external "
            "broadcasts need a signature-level permission and must validate "
            "the sender and every extra.", "CWE-925")
        for n, reason in hits[:30]:
            acts = [a.name() for a in n.find_all("action") if a.name()]
            f.add(self.ev(n, "exported", "receiver %s - %s; %s; actions: %s"
                          % (n.name() or "?", self.why_exported(n), reason,
                             ", ".join(acts[:5]) or "none")))
        return f

    # ---- 012 -------------------------------------------------------------
    def r012(self):
        hits = []
        if self.app is not None and self.app.a("taskAffinity") is not None:
            hits.append((self.app, "taskAffinity",
                         'application-wide android:taskAffinity="%s"'
                         % self.app.a("taskAffinity")))
        for n in self.mf.components("activity"):
            aff = n.a("taskAffinity")
            mode = (n.a("launchMode") or "").lower()
            if aff:
                hits.append((n, "taskAffinity",
                             'activity %s sets android:taskAffinity="%s"'
                             % (n.name() or "?", aff)))
            elif mode in ("singletask", "singleinstance") and self.exported(n):
                hits.append((n, "launchMode",
                             'exported activity %s uses launchMode="%s", so a '
                             "task started by another app can host it"
                             % (n.name() or "?", n.a("launchMode"))))
            if _true(n.a("allowTaskReparenting")):
                hits.append((n, "allowTaskReparenting",
                             "activity %s allows task reparenting"
                             % (n.name() or "?")))
        if not hits:
            return None
        f = Finding(
            "NOSAST-012", "Task Hijacking via taskAffinity",
            "MEDIUM" if self.target_sdk < 28 else "LOW",
            "A custom taskAffinity (or an exported singleTask activity) lets "
            "another app place itself in this app's task stack. In the "
            "StrandHogg pattern the malicious activity declares the victim's "
            "affinity with allowTaskReparenting, so launching the real app "
            "shows the attacker's screen on top of the real task - a "
            "pixel-perfect phishing prompt carrying the victim app's icon and "
            "recents entry."
            + (" Devices below API 28 have no platform mitigation."
               if self.target_sdk < 28 else ""),
            'Leave taskAffinity at its default or set it to "", avoid '
            "allowTaskReparenting, and keep targetSdk at 28+.", "CWE-1021")
        for n, attr, note in hits[:20]:
            f.add(self.ev(n, attr, note))
        return f

    # ---- 013 -------------------------------------------------------------
    def r013(self):
        hits = []
        for n in self.mf.root.find_all("meta-data"):
            nm, val = n.name(), (n.a("value") or "")
            if not val or val.startswith(("@0x", "?0x", "#")):
                continue
            if SECRET_VALUE.search(val):
                hits.append((n, nm, val, "the value matches a known secret "
                                         "format"))
            elif SECRET_NAME.search(nm) and len(val) >= 8:
                hits.append((n, nm, val, "the name looks like a credential and "
                                         "a literal value is inlined"))
        if not hits:
            return None
        f = Finding(
            "NOSAST-013", "Hardcoded Credentials In Manifest Metadata", "HIGH",
            "Secrets are inlined as <meta-data> values. The manifest is "
            "recoverable from the APK in seconds with no deobfuscation and no "
            "runtime access, so anyone who downloads the app holds these "
            "values. They cannot be rotated without a store release, and if "
            "the key authorises billable or privileged backend calls the whole "
            "user base shares one compromised credential.",
            "Move the secret server-side. Where a client identifier is "
            "unavoidable, restrict it at the provider (package name + signing "
            "certificate) and treat it as public.", "CWE-798")
        for n, nm, val, note in hits[:20]:
            shown = val if len(val) <= 28 else val[:14] + "..." + val[-8:]
            f.add(self.ev(n, "value", "%s = %s - %s" % (nm, shown, note)))
        return f

    # ---- 014 -------------------------------------------------------------
    def r014(self):
        """Only exported providers are reported here.

        exported="false" with grantUriPermissions="true" is the recommended
        FileProvider configuration, so it is deliberately not flagged.
        """
        hits = []
        for n in self.mf.components("provider"):
            is_fp = "fileprovider" in (n.name() or "").lower()
            grants = _true(n.a("grantUriPermissions"))
            if not (is_fp or grants) or not self.exported(n):
                continue
            perm, lvl = self.guard(n)
            if perm and "signature" in lvl:
                continue
            hits.append((n, perm, lvl))
        if not hits:
            return None
        f = Finding(
            "NOSAST-014", "Unprotected File Provider", "HIGH",
            "A FileProvider hands out content:// URIs that map to real paths "
            "inside the app sandbox. Exported, another app can enumerate and "
            "read those paths, and if the configured path root is broad "
            "(root-path, or files-path at '.') the mapping covers the whole "
            "data directory including shared_prefs and databases. A writable "
            "grant also lets the caller overwrite files the app later trusts.",
            'Keep the provider android:exported="false", pair '
            "grantUriPermissions with per-Intent "
            "FLAG_GRANT_READ_URI_PERMISSION, and narrow the file_paths XML to "
            "the single directory being shared - never root-path.",
            "CWE-552")
        for n, perm, lvl in hits[:20]:
            attr = "exported" if n.a("exported") is not None else "authorities"
            f.add(self.ev(n, attr, "provider %s (authorities=%s) is exported %s"
                          % (n.name() or "?", n.a("authorities") or "?",
                             "with no permission guard" if not perm
                             else "guarded only by %s (%s)" % (perm, lvl))))
            for md in n.find_all("meta-data")[:2]:
                f.add(self.ev(md, "resource",
                              "its path configuration is referenced here: %s"
                              % (md.a("resource") or md.a("value") or "?")))
        return f

    # ---- 015 -------------------------------------------------------------
    def r015(self):
        guarded = set()
        for tag in ("activity", "service", "provider", "receiver"):
            for n in self.mf.components(tag):
                p, _ = self.guard(n)
                if p:
                    guarded.add(p)
        hits = []
        for p in self.mf.custom_permissions():
            lvl = prot_level(p.a("protectionLevel"))
            if "signature" in lvl:
                continue
            hits.append((p, p.name(), lvl))
        if not hits:
            declared = self.mf.custom_permissions()
            if declared:
                self.ok("Custom Permissions Are Signature Level",
                        "Every permission the app declares requires the same "
                        "signing key, so another app cannot obtain it by "
                        "simply asking for it at install time.",
                        [self.ev(p, "protectionLevel",
                                 '%s has protectionLevel="%s"'
                                 % (p.name(), prot_level(
                                     p.a("protectionLevel"))))
                         for p in declared[:8]], "CWE-280")
            return None
        used = any(nm in guarded for _, nm, _ in hits)
        f = Finding(
            "NOSAST-015", "Custom Permission Misuse", "HIGH" if used else "MEDIUM",
            "Custom permissions are declared below signature protection "
            "level. Any third-party app can declare <uses-permission> for "
            "them and the system grants it silently at install time, so a "
            "permission used to gate a component provides no protection. "
            "Worse, on a device where this app is not yet installed a "
            "malicious app can define the same permission name first and own "
            "its protectionLevel.",
            'Declare internal permissions with '
            'android:protectionLevel="signature" and prefix the name with the '
            "app package.", "CWE-280")
        for p, nm, lvl in hits[:20]:
            f.add(self.ev(p, "protectionLevel",
                          '%s has protectionLevel="%s"%s'
                          % (nm, lvl, " and it guards an app component"
                             if nm in guarded else "")))
        return f

    # ---- 016 -------------------------------------------------------------
    def r016(self):
        acts = [n for n in self.mf.components("activity") if self.exported(n)]
        if len(acts) <= 5:
            return None
        f = Finding(
            "NOSAST-016", "Excessive Exported Activities", "MEDIUM",
            "%d activities are exported. Each is an independent external "
            "entry point whose Intent extras an attacker controls, and most "
            "are exported only because an <intent-filter> was added for "
            "internal navigation or a library requirement. The aggregate "
            "attack surface is far larger than the app's single launcher "
            "entry point implies." % len(acts),
            'Set android:exported="false" on everything that is not a '
            "deliberate external entry point and replace internal "
            "intent-filters with explicit Intents.", "CWE-926")
        for n in acts[:30]:
            f.add(self.ev(n, "exported",
                          "exported activity %s" % (n.name() or "?")))
        return f

    # ---- 017 -------------------------------------------------------------
    def r017(self):
        hits = []
        for n in self.mf.components("receiver"):
            if not self.exported(n):
                continue
            for a in n.find_all("action"):
                if a.name() in SENSITIVE_ACTIONS:
                    hits.append((a, n, a.name()))
        if not hits:
            return None
        f = Finding(
            "NOSAST-017", "Implicit Broadcast Handling", "MEDIUM",
            "The app registers exported receivers for implicit system "
            "broadcasts. Inbound, any app can forge these actions with an "
            "explicit Intent aimed at the component, so the handler runs on "
            "attacker-chosen data - a fake SMS_RECEIVED or push payload. "
            "Outbound, any implicit broadcast the app sends is delivered to "
            "every app with a matching filter, which is a silent data leak.",
            "Register volatile broadcasts at runtime with "
            "RECEIVER_NOT_EXPORTED, guard manifest receivers with a "
            "signature-level permission, and always send internal broadcasts "
            "explicitly.", "CWE-925")
        for a, n, act in hits[:25]:
            f.add(self.ev(a, "name", "receiver %s listens for %s while exported"
                          % (n.name() or "?", act)))
        return f

    # ---- 018 -------------------------------------------------------------
    def r018(self):
        app = self.app
        if app is None:
            return None
        v = app.a("allowBackup")
        if not (_true(v) or (v is None and self.min_sdk < 31)):
            return None
        full, rules = app.a("fullBackupContent"), app.a("dataExtractionRules")
        if full and rules:
            return None
        missing = []
        if not full:
            missing.append("android:fullBackupContent (API 23-30 exclusions)")
        if not rules:
            missing.append("android:dataExtractionRules (API 31+ cloud and "
                           "device-transfer exclusions)")
        f = Finding(
            "NOSAST-018", "Unencrypted Unfiltered Backups", "MEDIUM",
            "Backup is enabled but no exclusion ruleset is declared, so the "
            "whole private data directory is copied verbatim into every "
            "backup destination - local adb backup, cloud auto-backup and "
            "device-to-device transfer. Missing: %s. No custom BackupAgent "
            "re-encrypts the payload, and the local and transfer paths put "
            "those files somewhere the user's own PC can read."
            % "; ".join(missing),
            "Add both android:fullBackupContent and "
            "android:dataExtractionRules and exclude shared_prefs holding "
            'tokens plus every database, or set android:allowBackup="false".',
            "CWE-311")
        return f.add(self.ev(app, "allowBackup" if v is not None else None,
                             "backup is enabled and " + " and ".join(missing)
                             + " not declared"))

    # ---- 019 -------------------------------------------------------------
    def r019(self):
        hits = []
        for tag in ("activity", "activity-alias", "service", "receiver"):
            for n in self.mf.components(tag):
                if not self.exported(n):
                    continue
                weak, _ = self.unguarded(n)
                if not weak:
                    continue
                for intf in n.find_all("intent-filter"):
                    cats = [x.name() for x in intf.find_all("category")]
                    datas = intf.find_all("data")
                    schemes = [d.a("scheme") for d in datas if d.a("scheme")]
                    browsable = "android.intent.category.BROWSABLE" in cats
                    custom = [s for s in schemes
                              if s and s.lower() not in ("http", "https")]
                    if not (browsable or custom):
                        continue
                    why = []
                    if browsable:
                        why.append("BROWSABLE, so any web page can launch it "
                                   "with a tap or a redirect")
                    if custom:
                        why.append("custom scheme(s) %s that another app can "
                                   "also claim" % ", ".join(sorted(set(custom))[:3]))
                    if browsable and not _true(n.a("autoVerify")) and \
                            not _true(intf.a("autoVerify")) and \
                            any(s in ("http", "https") for s in schemes):
                        why.append("autoVerify is not set, so the link is not "
                                   "bound to a verified domain")
                    hits.append((intf, n, datas, "; ".join(why)))
        if not hits:
            return None
        f = Finding(
            "NOSAST-019", "Insecure Intent And Deep Link Handling", "HIGH",
            "Exported components accept deep links whose entire payload is "
            "attacker-supplied. The handler reads the URI and extras from "
            "getIntent(); if that value reaches a WebView loadUrl, a file "
            "path, a SQL selection, a redirect target or a startActivity "
            "call without validation, the deep link becomes the delivery "
            "vector for XSS-in-WebView, path traversal, injection or Intent "
            "redirection. A custom scheme can also be registered by another "
            "app, which intercepts the link and anything in it.",
            "Validate every deep-link URI against an allow-list of host and "
            "path, never pass Intent data straight into loadUrl or file APIs, "
            "reject nested Intents, and use verified App Links instead of "
            "custom schemes.", "CWE-939")
        for intf, n, datas, why in hits[:25]:
            focus = datas[0].line if datas else intf.line
            f.add(Ev(MANIFEST, focus, max(1, intf.line - 1),
                     min(intf.end_line + 1, len(self.mf.lines)),
                     "%s %s - %s" % (n.tag, n.name() or "?", why)))
        return f

    # ---- 020 -------------------------------------------------------------
    def r020(self):
        if self.u is None or self.max_sdk is None:
            return None
        f = Finding(
            "NOSAST-020", "maxSdkVersion Declared", "LOW",
            'android:maxSdkVersion="%s" caps the Android releases the app can '
            "run on. Users on newer platforms cannot install or keep it, "
            "which pushes them to sideload an older build or stay on an older "
            "OS, and it signals the app depends on behaviour the platform has "
            "since hardened. maxSdkVersion also silently drops permissions on "
            "newer devices, so code assuming a permission is held fails open."
            % self.max_sdk,
            "Remove android:maxSdkVersion and fix the underlying "
            "incompatibility instead.", "CWE-1104")
        return f.add(self.ev(self.u, "maxSdkVersion",
                             'android:maxSdkVersion="%s"' % self.max_sdk))

    # ---- 021 tapjacking --------------------------------------------------
    def r021(self):
        """Neither obscured-touch control exists anywhere in the APK.

        Both are searched for: android:filterTouchesWhenObscured in every
        decoded layout resource, and setFilterTouchesWhenObscured in the DEX
        string tables. If either turns up the app has the control and this is
        filed under Secured/ instead.
        """
        rows = self.sources[TAPJACK_FILE]
        if self.tapjack_ok:
            where = []
            if self.layout_guards:
                where.append("%d layout(s) set android:"
                             "filterTouchesWhenObscured" % len(self.layout_guards))
            if self.dex_guards:
                where.append("%d call site(s) to setFilterTouchesWhenObscured"
                             % sum(c for _f, c in self.dex_guards))
            ev = [Ev(TAPJACK_FILE, [self.tapjack_rows["result"]], 1, len(rows),
                     "; ".join(where))]
            for fname, line in self.layout_guards[:3]:
                ev.append(Ev(fname, line, max(1, line - 6), line + 6,
                             "android:filterTouchesWhenObscured is set here"))
            self.ok("Tapjacking Protection Present",
                    "The app filters touches delivered while its window is "
                    "obscured, so an overlay cannot pass taps through to the "
                    "real UI underneath.", ev, "CWE-1021")
            return None

        acts = self.mf.components("activity")
        if not acts:
            return None
        exported = [n for n in acts if self.exported(n)]
        f = Finding(
            "NOSAST-021", "Tapjacking Overlay Touch Hijacking",
            "HIGH" if exported else "MEDIUM",
            "Neither android:filterTouchesWhenObscured (layout resources) "
            "nor setFilterTouchesWhenObscured (compiled code) exists anywhere "
            "in this APK, so a malicious app "
            "holding SYSTEM_ALERT_WINDOW can draw a transparent window over "
            "this app's screens and let the user's taps pass straight through "
            "to the real UI underneath. The victim reads the attacker's "
            "prompt - 'Continue', 'Allow', a decoy keypad - and actually "
            "presses the underlying confirm, consent or transfer button. %s"
            % ("%d activities are externally launchable, so the attacker can "
               "bring the exact screen it wants to the foreground before "
               "overlaying it." % len(exported) if len(exported) > 1 else
               "One activity is externally launchable, so the attacker can "
               "bring that screen to the foreground before overlaying it."
               if exported else
               "No activity is exported, so the attacker must wait for the "
               "user to open the screen rather than summoning it."),
            'Set android:filterTouchesWhenObscured="true" on the root view of '
            "every screen that confirms an action (or call "
            "setFilterTouchesWhenObscured(true)), add FLAG_SECURE to "
            "sensitive screens, and call setHideOverlayWindows(true) on API "
            "31+ while a confirmation is shown.", "CWE-1021")
        # the search result itself, with both NOT FOUND rows marked
        f.add(Ev(TAPJACK_FILE,
                 [self.tapjack_rows["xml"], self.tapjack_rows["dex"]],
                 1, len(rows),
                 "neither control was found: the attribute is absent from "
                 "every layout and the setter is absent from every dex"))
        if "android.permission.SYSTEM_ALERT_WINDOW" in self.perms:
            f.add(self.ev(self.perms["android.permission.SYSTEM_ALERT_WINDOW"],
                          "name",
                          "the app itself holds SYSTEM_ALERT_WINDOW - the same "
                          "permission an overlay attack needs"))
        for n in (exported or acts)[:8]:
            f.add(self.ev(n, "name",
                          "activity %s renders UI with no obscured-touch "
                          "filter anywhere in its layouts" % (n.name() or "?")))
        # point at real layouts that take user input, so the gap is visible
        # in the resource rather than only argued from the manifest
        for name, doc, _ in self._input_layouts()[:5]:
            f.add(Ev(name, doc.root.line, 1,
                     min(len(doc.lines), doc.root.line + 14),
                     "this layout takes user input and its root view does not "
                     "set android:filterTouchesWhenObscured, so taps "
                     "delivered through an overlay are accepted"))
        return f

    def _input_layouts(self):
        """Layouts containing tappable / typable widgets come first."""
        with_input = [t for t in self.layout_files if t[2]]
        return with_input or self.layout_files

    # ---- 022 -------------------------------------------------------------
    def r022(self):
        s = self.sig
        if s["v3"] or s["v3.1"]:
            self.ok("APK Signature Scheme v3 Present",
                    "The APK carries a v3 signature block, so it has a "
                    "signing-certificate lineage and the signing key can be "
                    "rotated without changing the package name.",
                    self.sev("v3.1" if s["v3.1"] else "v3",
                             "the v3 block is present in the APK signing "
                             "block"), "CWE-347")
            return None
        f = Finding(
            "NOSAST-022", "Missing APK Signature Scheme v3", "MEDIUM",
            "The APK carries no v3 signature block and no v3.1. v3 carries "
            "the signing-certificate lineage, so without it the app can never "
            "rotate its signing key: the key in use today is the only key that "
            "will ever publish an update, and if it leaks the only recovery is "
            "a new package name and a forced reinstall by every user. v3 is "
            "also what lets the platform enforce knownSigner permissions. "
            "Present schemes: %s." % (", ".join(s["present"]) or "none"),
            "Sign with v3 enabled (default in build-tools 28+): apksigner "
            "sign --ks release.jks --v2-signing-enabled true "
            "--v3-signing-enabled true app.apk. If Play App Signing holds the "
            "key, enable key rotation in the console.", "CWE-347")
        return f.add(self.sev("v3", "no 0xf05368c0 (v3) and no 0x1b93ad61 "
                                    "(v3.1) block in the APK signing block"))

    # ---- 023 -------------------------------------------------------------
    def r023(self):
        s = self.sig
        if s["v4"]:
            self.ok("APK Signature Scheme v4 Present",
                    "A v4 signature accompanies the APK, so Android 11+ can "
                    "verify the package incrementally through fs-verity.",
                    self.sev("v4", "an .idsig sidecar accompanies the APK"),
                    "CWE-347")
            return None
        f = Finding(
            "NOSAST-023", "Missing APK Signature Scheme v4", "LOW",
            "No v4 signature is present - there is no <apk>.idsig beside the "
            "APK. v4 stores a Merkle hash tree so Android 11+ can verify the "
            "package incrementally while it streams, which is what fs-verity "
            "and ADB Incremental installs rely on. Without it the whole file "
            "must be hashed before anything runs, and the per-block integrity "
            "guarantee that would detect tampering of individual pages is "
            "unavailable. Present schemes: %s."
            % (", ".join(s["present"]) or "none"),
            "Produce the sidecar at sign time: apksigner sign --ks "
            "release.jks --v4-signing-enabled true app.apk, and ship "
            "app.apk.idsig with the APK. v4 is additive - it does not replace "
            "v2/v3.", "CWE-347")
        return f.add(self.sev("v4", "no %s.idsig file accompanies the APK"
                              % os.path.basename(self.apk.path)))

    # ---- 024 -------------------------------------------------------------
    def r024(self):
        s = self.sig
        problems = []
        if not (s["v2"] or s["v3"] or s["v3.1"]):
            problems.append(("v1", "the APK is signed with the v1 JAR scheme "
                                   "only"))
        if not problems:
            # the certificate itself is judged separately, in r026
            if not s["debug_cert"]:
                self.ok("APK Signed With A Modern Scheme",
                        "The archive is covered by v2/v3 whole-file signing, "
                        "so the Janus repackaging attack does not apply.",
                        self.sev("v3" if s["v3"] else "v2",
                                 "whole-file signing covers the whole "
                                 "archive, not just the zip entries"),
                        "CWE-347")
            return None
        f = Finding(
            "NOSAST-024", "Weak APK Signing v1 Only Janus", "HIGH",
            "v1 JAR signing covers individual zip entries, not the archive "
            "structure, which is what Janus (CVE-2017-13156) abuses: a DEX "
            "file prepended to a v1-only APK still verifies, so on affected "
            "devices an attacker ships a repackaged app the platform accepts "
            "as an update to the legitimate one, inheriting its data and "
            "permissions. A debug certificate is worse - its private key is "
            "the publicly known androiddebugkey from the Android SDK, so "
            "anyone can sign a replacement build the device treats as the "
            "same app.",
            "Re-sign with v2 and v3 enabled using a private release keystore, "
            "and verify with apksigner verify --verbose --print-certs that "
            "the certificate is yours.", "CWE-347")
        for key, note in problems:
            f.add(self.sev(key, note))
        return f

    # ---- 026 signed with the Android debug certificate --------------------
    def r026(self):
        """Is the signing certificate the SDK's debug certificate?

        Read from the v1 PKCS#7 blob, or - when the APK has no v1 signature -
        from the certificates inside the v2/v3 signing block, so the check
        still applies to a v3-only release.
        """
        s = self.sig
        dn = s["dn"]
        if not s["debug_cert"]:
            if dn.get("CN"):
                self.ok("Release Signing Certificate",
                        "The APK is signed with a real certificate rather "
                        "than the Android SDK debug key, so a third party "
                        "cannot produce a build the device accepts as this "
                        "app.",
                        self.sev("debug",
                                 "subject CN=%s - not the debug certificate"
                                 % dn["CN"][0]), "CWE-347")
            return None

        shown = ", ".join("%s=%s" % (k, v[0]) for k, v in dn.items() if v)
        f = Finding(
            "NOSAST-026", "Signed With The Android Debug Certificate",
            "CRITICAL",
            "The signing certificate is the Android SDK debug certificate "
            "(%s). Its private key is not secret: every Android SDK "
            "installation generates ~/.android/debug.keystore and the "
            "keystore password, key alias and key password are the fixed, "
            "published values 'android' / 'androiddebugkey' / 'android'. "
            "Anyone can therefore sign a modified build that the platform "
            "treats as the same application - it installs straight over the "
            "real one as an update and inherits its data directory, its "
            "granted permissions and any signature-level permission it "
            "holds. Every control that rests on the signing identity "
            "collapses with it: signature-level permission guards, "
            "Play Integrity and attestation checks, and backend pinning of "
            "the app certificate. A debug certificate in a shipped build "
            "also usually means the release signing config was never applied, "
            "so the build may carry other debug settings as well."
            % (shown or "CN=Android Debug"),
            "Re-sign the release with a private keystore held outside the "
            "repository and verify with `apksigner verify --verbose "
            "--print-certs app.apk` that the subject is your organisation. "
            "Wire the release signingConfig into the release buildType so a "
            "debug-signed artefact cannot be produced by the release task, "
            "and prefer Play App Signing so the upload key can be rotated if "
            "it leaks.", "CWE-321")
        f.add(self.sev("debug", "the certificate subject is the SDK debug "
                                "certificate"))
        for short in ("CN", "O", "C"):
            key = "dn_" + short
            if key in self.sig_idx:
                f.add(self.sev(key, "%s=%s matches the debug certificate"
                               % (short, dn[short][0])))
        return f

    # ---- 025 SQL recovered by reverse engineering ------------------------
    def r025(self):
        """SQL literals lifted out of the DEX string tables.

        Every statement the app builds is partly present in the APK, because
        the literal fragments have to be. Statements that stop mid-expression
        (`... WHERE id = `) or carry a %s were completed by concatenation at
        runtime, which is the shape SQL injection takes on Android.
        """
        if not self.sql_count:
            return None
        risky = self.sql_risky
        f = Finding(
            "NOSAST-025", "SQL Queries Recovered By Reverse Engineering",
            "HIGH" if risky else "MEDIUM",
            "%d SQL statements were lifted straight out of the DEX string "
            "tables - no decompiler, no device, just the published APK. That "
            "alone hands an attacker the database schema: table names, column "
            "names and the queries the app runs against them, which is the "
            "map for attacking an exported provider or a stolen database "
            "file.%s"
            % (self.sql_count,
               " %d of them stop mid-expression or carry a format "
               "placeholder, so the missing value is concatenated in at "
               "runtime rather than bound as a parameter. Wherever that value "
               "comes from outside the app - an Intent extra, a provider "
               "selection argument, a deep link, a server response - the "
               "caller controls SQL syntax and not just data, and can read or "
               "modify every table in the database." % len(risky)
               if risky else
               " None of them show concatenation markers, so review is still "
               "worthwhile but no injection point is evident from the "
               "literals alone."),
            "Bind every value: rawQuery(sql, new String[]{...}) with ? "
            "placeholders, ContentValues for writes, or Room with typed "
            "@Query parameters. Column names and sort order cannot be bound, "
            "so validate those against an allow-list. Treat the recovered "
            "schema as public and enforce authorisation server-side rather "
            "than relying on the client's queries.", "CWE-89")
        if risky:
            for row in risky[:12]:
                f.add(Ev(SQL_FILE, row, max(1, row - 6), row + 6,
                         "this statement is completed by concatenation at "
                         "runtime"))
        else:
            last = self.sql_head + min(self.sql_count, 18)
            f.add(Ev(SQL_FILE, list(range(self.sql_head + 1, last + 1)),
                     1, last,
                     "%d SQL statements are readable in the APK"
                     % self.sql_count))
        return f


# ===========================================================================
#  SECTION 5 - screenshot renderer
# ===========================================================================
# flat colours, no shadows anywhere: the highlight is colour plus a left rule
BG = (255, 255, 255)
FG = (28, 29, 32)
MUT = (106, 110, 117)
LINE = (226, 228, 232)
GUT_BG = (246, 247, 249)
GUT_FG = (150, 155, 162)
RED = (211, 32, 41)
RED_BG = (253, 236, 237)
RED_RULE = (211, 32, 41)
GREEN = (22, 125, 62)

SEV_COLOR = {
    "CRITICAL": (176, 0, 32), "HIGH": (211, 32, 41),
    "MEDIUM": (199, 84, 0), "LOW": (122, 106, 0), "INFO": (69, 96, 122),
}

MONO_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\lucon.ttf",
    r"C:\Windows\Fonts\cour.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Menlo.ttc",
]
MONO_BOLD = [
    r"C:\Windows\Fonts\consolab.ttf", r"C:\Windows\Fonts\courbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
]
SANS = [
    r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
SANS_BOLD = [
    r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def _font(paths, size):
    for p in paths:
        if os.path.isfile(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    try:
        return ImageFont.load_default(size)
    except TypeError:          # Pillow < 9.2
        return ImageFont.load_default()


class Shot:
    """Renders one finding + one evidence window to a PNG."""

    PAD = 26
    CODE_SIZE = 15
    TITLE_SIZE = 23
    META_SIZE = 14
    NOTE_SIZE = 15
    MAX_COLS = 150

    def __init__(self):
        self.mono = _font(MONO_CANDIDATES, self.CODE_SIZE)
        self.mono_b = _font(MONO_BOLD or MONO_CANDIDATES, self.CODE_SIZE)
        self.title = _font(SANS_BOLD, self.TITLE_SIZE)
        self.meta = _font(MONO_CANDIDATES, self.META_SIZE)
        self.note = _font(SANS, self.NOTE_SIZE)
        self.note_b = _font(SANS_BOLD, self.NOTE_SIZE)
        probe = Image.new("RGB", (10, 10))
        d = ImageDraw.Draw(probe)
        self.cw = d.textlength("M" * 50, font=self.mono) / 50.0
        self.ch = self.CODE_SIZE + 7
        self.lh = self.NOTE_SIZE + 7

    def render(self, finding, ev, lines, path, app_label):
        """The code window, and nothing else.

        The flagged row gets a red rectangle drawn around it and its text in
        red. Every other row in the window is left exactly as it is - no
        lines removed, no commentary added.
        """
        ok = (finding.severity == "SECURE")
        mark = GREEN if ok else RED
        start = max(1, min(ev.start, len(lines) or 1))
        end = max(start, min(ev.end, len(lines) or 1))
        body = lines[start - 1:end] if lines else ["(source unavailable)"]
        focus = set(ev.focus)

        probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
        gutter_digits = max(2, len(str(end)))
        gutter_w = int(self.cw * (gutter_digits + 2)) + 14
        code_x = self.PAD + gutter_w + 12

        longest = max([len(t) for t in body] + [36])
        content_w = int(max(560, min(1760,
                                     code_x + self.cw * longest + 16 + self.PAD)))
        cols = int((content_w - code_x - 16 - self.PAD) / self.cw)
        body = [t if len(t) <= cols else t[:max(8, cols - 1)] + "…"
                for t in body]

        code_h = len(body) * self.ch + 20
        img = Image.new("RGB", (content_w, int(code_h + 2 * self.PAD)), BG)
        d = ImageDraw.Draw(img)

        top, bot = self.PAD, self.PAD + code_h
        d.rectangle([self.PAD, top, content_w - self.PAD, bot],
                    fill=BG, outline=LINE)
        d.rectangle([self.PAD, top, self.PAD + gutter_w, bot], fill=GUT_BG)
        d.line([self.PAD + gutter_w, top, self.PAD + gutter_w, bot], fill=LINE)

        ry = top + 10
        for n, text in enumerate(body, start):
            hit = n in focus
            if hit:
                d.rectangle([self.PAD + 3, ry - 4,
                             content_w - self.PAD - 3, ry + self.ch - 5],
                            outline=mark, width=2)
            d.text((self.PAD + 12, ry), str(n).rjust(gutter_digits),
                   font=self.mono_b if hit else self.mono,
                   fill=mark if hit else GUT_FG)
            d.text((code_x, ry), text,
                   font=self.mono_b if hit else self.mono,
                   fill=mark if hit else FG)
            ry += self.ch

        img.save(path, "PNG", optimize=True)
        return path


# ===========================================================================
#  SECTION 6 - driver
# ===========================================================================
GITHUB = "https://github.com/d1n3sh-0x3/"
LINKEDIN = "https://www.linkedin.com/in/dinesh-goud"

TAGLINES = [
    "NO-SAST :: static analysis, screenshotted",
    "NO-SAST :: unpack. decode. highlight.",
    "NO-SAST :: the manifest never lies",
    "NO-SAST :: red line, real line",
    "NO-SAST :: dex in, evidence out",
    "NO-SAST :: no agent, no device, no excuses",
    "NO-SAST :: every finding is a screenshot",
]


def hex_art(tag=None):
    """A hexdump banner over a random tagline, with random trailing noise."""
    import random
    payload = ((tag or random.choice(TAGLINES)).encode("ascii", "ignore")
               + b"\x00" + os.urandom(random.randint(9, 25)))
    out = []
    for off in range(0, len(payload), 16):
        chunk = payload[off:off + 16]
        cols = " ".join("%02x" % b for b in chunk)
        if len(chunk) > 8:
            cols = cols[:23] + " " + cols[23:]
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("  %08x  %-49s |%s|" % (off, cols, txt))
    return out


def safe(s, limit=70):
    s = re.sub(r"[^A-Za-z0-9._\- ]+", "_", str(s)).strip(" ._-")
    s = re.sub(r"\s+", "_", s)
    return (s or "unnamed")[:limit]


def app_label(apk, mf):
    """Directory name for the app: label if it is a literal, else package."""
    app = mf.application
    lbl = app.a("label") if app is not None else None
    if lbl and not lbl.startswith(("@0x", "?0x", "@")) and len(lbl) > 1:
        return safe(lbl)
    pkg = mf.package
    if pkg and pkg != "unknown.package":
        return safe(pkg)
    return safe(os.path.splitext(os.path.basename(apk.path))[0])


def ask_apk():
    print("Drag the APK onto this window, or paste its path, then Enter.")
    while True:
        try:
            raw = input("APK > ").strip().strip('"').strip("'")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if raw and os.path.isfile(raw):
            return raw
        if raw:
            print("  not a file: %s" % raw)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nosast",
        description="Scan an APK and screenshot every finding with the "
                    "vulnerable line highlighted in red.")
    ap.add_argument("apk", nargs="?", help="path to the APK (prompted if "
                                           "omitted)")
    ap.add_argument("-o", "--out", default=".",
                    help="where to create the <AppName> directory "
                         "(default: current directory)")
    ap.add_argument("--context", type=int, default=7,
                    help="lines of context kept above and below the "
                         "highlighted line (default 7)")
    ap.add_argument("--max-shots", type=int, default=12,
                    help="most images per issue (default 12)")
    args = ap.parse_args(argv)

    path = args.apk or ask_apk()
    if not path:
        print("no APK given")
        return 2
    path = os.path.abspath(path.strip('"').strip("'"))
    if not os.path.isfile(path):
        print("[!] no such file: %s" % path)
        return 2

    print("=" * 72)
    for row in hex_art():
        print(row)
    print("=" * 72)
    print(" NO-SAST  -  %s" % os.path.basename(path))
    print("=" * 72)

    try:
        apk = Apk(path)
    except Exception as e:
        print("[!] cannot open the APK: %s" % e)
        return 2
    try:
        scan = Scan(apk)
    except Exception as e:
        print("[!] cannot decode AndroidManifest.xml: %s" % e)
        return 2

    label = app_label(apk, scan.mf)
    print("package   %s" % scan.mf.package)
    print("sdk       min=%s target=%s%s"
          % (scan.min_sdk or "?", scan.target_sdk or "?",
             " max=%s" % scan.max_sdk if scan.max_sdk else ""))
    print("signing   present: %s   missing: %s"
          % (", ".join(apk.sig["present"]) or "none",
             ", ".join(apk.sig["missing"]) or "none"))
    print("layouts   %d decoded, %d with an obscured-touch filter"
          % (len(scan.layout_files), len(scan.layout_guards)))

    print("\nscanning ...")
    for row in hex_art("%s :: %d dex :: %d layouts :: %d sql"
                       % (scan.mf.package, len(apk.dex_files()),
                          len(scan.layout_files), scan.sql_count)):
        print(row)

    findings = scan.run()
    if not findings and not scan.secure:
        print("\nno findings")
        print(" %s" % GITHUB)
        
        return 0

    root = os.path.join(os.path.abspath(args.out), label)
    os.makedirs(root, exist_ok=True)
    shot = Shot()

    def write(f, folder):
        """One PNG per evidence location. Returns how many were written."""
        os.makedirs(folder, exist_ok=True)
        n = 0
        for ev in f.ev[:args.max_shots]:
            lines = scan.sources.get(ev.file)
            if not lines:
                continue
            if args.context != 7 and ev.focus:
                ev.start = max(1, min(ev.focus) - args.context)
                ev.end = max(ev.focus) + args.context
            n += 1
            stem = re.sub(r"\.(xml|txt)$", "", ev.file).replace("/", "_")
            # keep the name short: Windows still caps the full path at 260
            if len(ev.focus) <= 3:
                tag = "-".join(map(str, ev.focus)) or "0"
            else:
                tag = "%d-%d_x%d" % (ev.focus[0], ev.focus[-1], len(ev.focus))
            name = "%02d_%s_L%s.png" % (n, safe(stem, 40), tag)
            try:
                shot.render(f, ev, lines, os.path.join(folder, name), label)
            except Exception as e:
                print("            [!] image failed: %s" % e)
                n -= 1
                continue
            print("            %s" % name)
        extra = len(f.ev) - n
        if extra > 0:
            print("            (+%d more, raise --max-shots)" % extra)
        return n

    counts, total = {}, 0
    print("\nwriting screenshots under %s\n" % root)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        print("[%-8s] %s" % (f.severity, f.title))
        total += write(f, os.path.join(root, f.dirname()))

    sec_total = 0
    if scan.secure:
        print("\n[SECURED ] %d control(s) correctly configured" % len(scan.secure))
        for f in scan.secure:
            print("            %s" % f.title)
            sec_total += write(f, os.path.join(root, "Secured", f.dirname()))

    print("\n" + "=" * 72)
    print(" %s" % "   ".join("%s %d" % (s, counts[s])
                             for s in SEV_ORDER if s in counts))
    print(" %d issue(s), %d screenshot(s)" % (len(findings), total))
    if scan.secure:
        print(" %d secure control(s), %d screenshot(s) in Secured/"
              % (len(scan.secure), sec_total))
    print(" %s" % root)
    print("=" * 72)
    print(" %s" % GITHUB)
    
    print("=" * 72)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
