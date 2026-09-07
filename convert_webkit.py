#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert_webkit.py — Etape 2/2 du pipeline.

Convertit les listes adblock brutes (filters/) en Content Blocker JSON natif
WebKit / Safari (webkit-rules/Webkit-<Nom>.json).

Principe directeur: on n'ecrit QUE ce que WebKit sait reellement compiler et
appliquer. Toute regle dont la semantique ne peut pas etre rendue fidelement est
ecartee et comptabilisee dans un rapport, plutot que traduite approximativement.

Reference du format:
  trigger : url-filter (obligatoire), url-filter-is-case-sensitive, if-domain,
            unless-domain, if-top-url, unless-top-url, resource-type, load-type,
            load-context (Safari 15+)
  action  : block, block-cookies, css-display-none (+selector),
            ignore-previous-rules, make-https

Usage:
    python3 convert_webkit.py
    python3 convert_webkit.py --only AdGuard-Base
    python3 convert_webkit.py --legacy --pretty
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IN = os.path.join(ROOT, "filters")
DEFAULT_OUT = os.path.join(ROOT, "webkit-rules")
DEFAULT_REPORTS = os.path.join(ROOT, "reports")
DEFAULT_EXTENDED = os.path.join(ROOT, "extended-rules")
PREFIX = "Webkit-"
EXT_PREFIX = "Extended-"

# Limite dure de Safari: 150 000 regles par content blocker compile.
WEBKIT_MAX_RULES = 150000


# --------------------------------------------------------------------------- #
# Tables de correspondance
# --------------------------------------------------------------------------- #

# Types WebKit modernes (Safari 15+) et classiques.
RESOURCE_TYPES_MODERN = {
    "document": ["document"],
    "subdocument": ["document"],          # + load-context child-frame
    "image": ["image"],
    "stylesheet": ["style-sheet"],
    "script": ["script"],
    "font": ["font"],
    "media": ["media"],
    "xmlhttprequest": ["fetch"],
    "websocket": ["websocket"],
    "ping": ["ping"],
    "beacon": ["ping"],
    "other": ["other"],
    "object": ["other"],
    "object-subrequest": ["other"],
    "popup": ["popup"],
}

RESOURCE_TYPES_LEGACY = {
    "document": ["document"],
    "subdocument": ["document"],
    "image": ["image"],
    "stylesheet": ["style-sheet"],
    "script": ["script"],
    "font": ["font"],
    "media": ["media"],
    "xmlhttprequest": ["raw"],
    "websocket": ["raw"],
    "ping": ["raw"],
    "beacon": ["raw"],
    "other": ["raw"],
    "object": ["raw"],
    "object-subrequest": ["raw"],
    "popup": ["popup"],
}

ALL_TYPES_MODERN = ["document", "image", "style-sheet", "script", "font",
                    "media", "popup", "fetch", "websocket", "ping", "other",
                    "svg-document"]
ALL_TYPES_LEGACY = ["document", "image", "style-sheet", "script", "font",
                    "media", "popup", "raw", "svg-document"]

# Alias de modificateurs (uBlock Origin / AdGuard) ramenes au nom canonique.
MODIFIER_ALIASES = {
    "xhr": "xmlhttprequest", "css": "stylesheet", "frame": "subdocument",
    "doc": "document", "ghide": "generichide", "ehide": "elemhide",
    "shide": "specifichide", "from": "domain", "3p": "third-party",
    "1p": "first-party", "popunder": "popup", "queryprune": "removeparam",
    "object-subrequest": "object", "beacon": "ping", "xhr-request": "xmlhttprequest",
}

# Modificateurs sans equivalent WebKit: la regle entiere est ecartee.
UNSUPPORTED_MODIFIERS = {
    "csp", "redirect", "redirect-rule", "removeparam", "removeheader", "replace",
    "hls", "jsonprune", "permissions", "referrerpolicy", "method", "to", "header",
    "app", "network", "extension", "stealth", "denyallow", "webrtc", "empty",
    "mp4", "inline-script", "inline-font", "genericblock", "generichide",
    "elemhide", "jsinject", "content", "urlblock", "badfilter", "specifichide",
    "strict-first-party", "strict-third-party", "cookie", "stealth-mode",
    "ctag", "dnsrewrite", "dnstype", "client", "path", "url", "urlskip",
    "uritransform", "strict3p", "strict1p", "reason", "ipaddress", "cname",
    "webrtc", "websocket-request", "match-case-value",
}

# Modificateurs sans effet cote WebKit mais inoffensifs: on garde la regle.
IGNORED_MODIFIERS = {"important", "all", "not-important"}

# Pseudo-classes etendues (AdGuard / uBO) non comprises par le moteur CSS
# du content blocker.
EXTENDED_CSS_TOKENS = (
    ":has-text(", ":contains(", ":matches-css", ":matches-attr", ":matches-path",
    ":matches-property", ":min-text-length(", ":xpath(", ":nth-ancestor(",
    ":upward(", ":watch-attr(", ":remove()", ":remove(", ":style(", ":-abp-",
    ":if(", ":if-not(", ":properties(", ":others(", "##^",
)

# Constructions regex hors du sous-ensemble accepte par WebKit.
BAD_REGEX_TOKENS = ("{", "}", "(?", "\\d", "\\w", "\\s", "\\D", "\\W", "\\S",
                    "\\b", "\\B", "*?", "+?", "??", "|", "\\1", "\\2", "\\3")

COSMETIC_MARKERS = ["#@$?#", "#@$#", "#@?#", "#@%#", "#@#",
                    "#$?#", "#$#", "#?#", "#%#", "##"]

# `exemple.*` n'existe pas cote WebKit. On l'etend vers les extensions
# reellement rencontrees dans l'ecosysteme adblock. C'est une approximation
# bornee: elle peut viser un TLD inexistant (sans effet) mais ne peut pas
# deborder sur un autre nom de domaine.
TLD_EXPANSION = (
    "com net org io co to me tv cc xyz top site online info biz club live fun "
    "store art one pro vip ws la is in ru ua by kz de fr it es nl pl pt br mx "
    "ar cl pe cn jp kr id vn th tw hk sg my ph se no dk fi cz sk hu ro bg gr "
    "tr be ch at ie nz au ca us uk eu dev app link click space website host "
    "press blog cyou icu buzz life world today news media digital cloud "
    "network group agency plus best wiki quest sbs shop lat cfd bond "
    "co.uk com.br com.mx com.ar com.tr com.ua com.au co.jp co.kr com.cn"
).split()

HOSTS_LINE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)[ \t]+(\S+)")
DOMAIN_OK = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$")


class Unsupported(Exception):
    """Regle non convertible: le message sert de motif dans le rapport."""


# --------------------------------------------------------------------------- #
# Pattern adblock -> url-filter (regex WebKit)
# --------------------------------------------------------------------------- #

# `||` : n'importe quel schema http/https/ws/wss, suivi d'un nombre quelconque
# de sous-domaines. `(...)*` reste dans le sous-ensemble regex de WebKit.
ANCHOR_DOMAIN = r"^[htpsw]+://([a-z0-9-]+\.)*"
# Separateur `^` en milieu de motif: optionnel (comme AdGuard) pour ne pas
# rater les fins de segment.
SEP_MID = r"[/:&?=,;]?"
# Separateur `^` en fin de motif: obligatoire. WebKit teste une URL canonique
# qui contient toujours au moins `/`, donc c'est sur — et cela evite le faux
# positif classique `||exemple.com^` matchant `exemple.com.pirate.net`.
SEP_END = r"[/:&?=,;]"

REGEX_ESCAPE = set(".+?()[]{}|^$\\*")


def percent_encode_non_ascii(s):
    out = []
    for ch in s:
        if ord(ch) < 128:
            out.append(ch)
        else:
            out.extend("%%%02X" % b for b in ch.encode("utf-8"))
    return "".join(out)


def idna_normalize(pattern):
    """Punycode l'hote si le motif contient de l'Unicode, sinon renvoie tel quel."""
    if all(ord(c) < 128 for c in pattern):
        return pattern
    m = re.match(r"^(\|\||\|)?([^/^*|$]+)(.*)$", pattern, re.S)
    if m:
        prefix, host, rest = m.group(1) or "", m.group(2), m.group(3)
        try:
            host = host.encode("idna").decode("ascii")
            return prefix + host + percent_encode_non_ascii(rest)
        except Exception:  # noqa: BLE001
            pass
    return percent_encode_non_ascii(pattern)


# WebKit refuse `\d` `\w` `\s` mais accepte les classes explicites: ce sont
# des synonymes exacts, la reecriture ne perd rien. (Verifie: tools/wk_probe)
SHORTHAND = {"d": ("[0-9]", "0-9"),
             "w": ("[a-zA-Z0-9_]", "a-zA-Z0-9_"),
             "s": ("[ ]", " ")}


def rewrite_shorthand(rx):
    """Remplace \d \w \s par leur classe equivalente, dedans comme dehors."""
    out, i, in_class = [], 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            nxt = rx[i + 1]
            if nxt in SHORTHAND:
                out.append(SHORTHAND[nxt][1 if in_class else 0])
                i += 2
                continue
            out.append(c)
            out.append(nxt)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        out.append(c)
        i += 1
    return "".join(out)


def _split_top_level(text, sep="|"):
    """Decoupe sur `sep` a profondeur 0, hors classes et hors echappements."""
    parts, buf, depth, in_class, esc = [], [], 0, False, False
    for ch in text:
        if esc:
            buf.append(ch); esc = False; continue
        if ch == "\\":
            buf.append(ch); esc = True; continue
        if in_class:
            buf.append(ch)
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True; buf.append(ch); continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf)); buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _match_paren(rx, start):
    depth, in_class, esc = 0, False, False
    i = start
    while i < len(rx):
        c = rx[i]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def expand_alternations(rx, limit=24):
    """`(a|b)` -> deux regex distinctes. WebKit ne sait pas faire de disjonction,
    mais deux regles valent exactement une alternation."""
    top = _split_top_level(rx)
    if len(top) > 1:
        out = []
        for alt in top:
            out.extend(expand_alternations(alt, limit))
            if len(out) > limit:
                raise Unsupported("expansion d'alternation trop large")
        return out

    i, in_class, esc = 0, False, False
    while i < len(rx):
        c = rx[i]
        if esc:
            esc = False; i += 1; continue
        if c == "\\":
            esc = True; i += 1; continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1; continue
        if c == "[":
            in_class = True; i += 1; continue
        if c == "(":
            j = _match_paren(rx, i)
            if j is None:
                raise Unsupported("parentheses desequilibrees")
            alts = _split_top_level(rx[i + 1:j])
            if len(alts) > 1:
                # `(a|b)*` et `(a|b)+` ne se scindent pas sans perte
                # ("ab" appartient a (a|b)+ mais ni a a+ ni a b+).
                if rx[j + 1:j + 2] in ("*", "+", "{"):
                    raise Unsupported("alternation sous quantificateur")
                out = []
                for a in alts:
                    for v in expand_alternations(rx[:i] + "(" + a + ")" + rx[j + 1:], limit):
                        out.append(v)
                        if len(out) > limit:
                            raise Unsupported("expansion d'alternation trop large")
                return out
            i = j + 1
            continue
        i += 1
    return [rx]


def misplaced_anchor(rx):
    """`^` ailleurs qu'en tete, ou `$` ailleurs qu'en fin: refuses par WebKit.

    Verifie sur le compilateur systeme (voir tools/wk_probe.swift).
    """
    i, in_class, esc = 0, False, False
    while i < len(rx):
        c = rx[i]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "^" and i != 0:
            return True
        elif c == "$" and i != len(rx) - 1:
            return True
        i += 1
    return False


def validate_raw_regex(rx):
    """Retourne la liste des regex WebKit equivalentes (1, ou N si alternation)."""
    if not rx:
        raise Unsupported("regex vide")
    if any(ord(c) > 127 for c in rx):
        raise Unsupported("regex non-ASCII")
    rx = rewrite_shorthand(rx)
    variants = expand_alternations(rx)
    out = []
    for v in variants:
        if any(t in v for t in BAD_REGEX_TOKENS):
            raise Unsupported("regex hors du sous-ensemble WebKit")
        if misplaced_anchor(v):
            raise Unsupported("ancre `^` ou `$` mal placee")
        try:
            re.compile(v)
        except re.error:
            raise Unsupported("regex invalide")
        out.append(v)
    return out


def pattern_to_url_filter(pattern):
    """Traduit un motif adblock en liste d'`url-filter` WebKit (1, ou N si
    l'alternation d'une regex a du etre eclatee). Leve Unsupported."""
    pattern = pattern.strip()
    if not pattern or pattern in ("*", "||", "|"):
        return [".*"]

    if len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
        return validate_raw_regex(pattern[1:-1])

    pattern = idna_normalize(pattern)
    if any(ord(c) > 127 for c in pattern):
        raise Unsupported("motif non-ASCII non normalisable")

    out = []
    i = 0
    n = len(pattern)

    if pattern.startswith("||"):
        out.append(ANCHOR_DOMAIN)
        i = 2
    elif pattern.startswith("|"):
        out.append("^")
        i = 1

    end_anchor = False
    if pattern.endswith("|") and not pattern.endswith("\\|"):
        n -= 1
        end_anchor = True

    while i < n:
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(SEP_END if i == n - 1 else SEP_MID)
        elif ch == "|":
            raise Unsupported("ancre `|` en milieu de motif")
        elif ch in REGEX_ESCAPE:
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1

    if end_anchor:
        out.append("$")

    rx = "".join(out)
    if "{" in rx or "}" in rx:
        raise Unsupported("accolade litterale (refusee par le parseur WebKit)")
    # `.*` en tete est inutile et couteux a compiler.
    while rx.startswith(".*") and not rx.startswith(".*$"):
        rx = rx[2:]
    if not rx:
        return [".*"]
    try:
        re.compile(rx)
    except re.error:
        raise Unsupported("regex generee invalide")
    return [rx]


# --------------------------------------------------------------------------- #
# Parsing des modificateurs
# --------------------------------------------------------------------------- #

def split_options(text):
    """Separe `pattern$opt1,opt2`. Gere les motifs regex `/.../$opts`."""
    if text.startswith("/"):
        # Le `/` fermant est le premier non echappe suivi de rien ou de `$`.
        # `rfind` se ferait piéger par une regex dans la valeur d'un
        # modificateur, ex. /re/$document,removeparam=/^=$/.
        i, closers = 1, []
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == "/":
                closers.append(i)
            i += 1
        # Un `/` suivi de `$` prime sur le `/` final: sinon une valeur de
        # modificateur qui est elle-meme une regex (ex. $domain=/re/) serait
        # avalee dans le motif.
        for i in closers:
            if text[i + 1:].startswith("$"):
                return text[:i + 1], text[i + 2:]
        if closers and closers[-1] == len(text) - 1:
            return text, ""
    idx = -1
    for m in re.finditer(r"(?<!\\)\$", text):
        rest = text[m.end():]
        if re.match(r"^~?[a-z0-9-]+([=,]|$)", rest):
            idx = m.start()
    if idx == -1:
        return text, ""
    return text[:idx], text[idx + 1:]


def split_modifiers(opts):
    """Decoupe sur les virgules hors valeurs entre parentheses/regex."""
    parts, buf, depth, in_re = [], [], 0, False
    i = 0
    while i < len(opts):
        c = opts[i]
        if c == "\\":
            buf.append(c)
            if i + 1 < len(opts):
                i += 1
                buf.append(opts[i])
            i += 1
            continue
        if c == "/" and buf and buf[-1] == "=":
            in_re = not in_re
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        if c == "," and depth == 0 and not in_re:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def normalize_domain(d, expand_tld=True):
    """Retourne la liste des domaines WebKit (`*d` = domaine + sous-domaines).

    `exemple.*` est etendu vers TLD_EXPANSION; toute autre forme de joker est
    inexprimable et renvoie une liste vide.
    """
    d = d.strip().lower().rstrip(".")
    if not d or d.startswith("/"):
        return []
    if d.endswith(".*"):
        if not expand_tld:
            return []
        base = d[:-2]
        if "*" in base or not base:
            return []
        out = []
        for tld in TLD_EXPANSION:
            got = normalize_domain("%s.%s" % (base, tld), expand_tld=False)
            out.extend(got)
        return out
    if "*" in d or "~" in d[1:]:
        return []
    if any(ord(c) > 127 for c in d):
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:  # noqa: BLE001
            return []
    if not DOMAIN_OK.match(d):
        return []
    return ["*" + d]


def parse_domain_option(value):
    """`a.com|~b.com` -> (inclus, exclus, nb_ignores)."""
    inc, exc, dropped = [], [], 0
    for raw in value.split("|"):
        raw = raw.strip()
        if not raw:
            continue
        neg = raw.startswith("~")
        doms = normalize_domain(raw[1:] if neg else raw)
        if not doms:
            dropped += 1
            continue
        (exc if neg else inc).extend(doms)
    return inc, exc, dropped


# --------------------------------------------------------------------------- #
# Convertisseur
# --------------------------------------------------------------------------- #

def normalize_modifiers(mods, drop=None):
    """Cle canonique d'un jeu de modificateurs, pour apparier un $badfilter."""
    out = []
    for m in mods:
        m = m.strip()
        name = m.lstrip("~").split("=", 1)[0].strip().lower()
        if drop and name == drop:
            continue
        if name in ("domain", "from") and "=" in m:
            head, val = m.split("=", 1)
            val = "|".join(sorted(v.strip() for v in val.split("|") if v.strip()))
            m = "%s=%s" % (head, val)
        out.append(m)
    return tuple(sorted(out))


def rule_key(line, drop=None):
    """Identite d'une regle reseau, insensible a l'ordre des modificateurs."""
    exception = line.startswith("@@")
    if exception:
        line = line[2:]
    pattern, opts = split_options(line)
    mods = split_modifiers(opts) if opts else []
    return (exception, pattern, normalize_modifiers(mods, drop))


SCRIPTLET_AG = re.compile(r"^//\s*scriptlet\s*\((.*)\)\s*;?\s*$", re.S)
SCRIPTLET_UBO = re.compile(r"^\+js\((.*)\)\s*$", re.S)


def parse_quoted_args(inner):
    """Arguments d'un //scriptlet(...) AdGuard: quotes simples ou doubles,
    echappements par backslash, virgules hors quotes."""
    args, buf, quote, esc = [], [], None, False
    started = False
    for ch in inner:
        if esc:
            buf.append(ch); esc = False; continue
        if ch == "\\":
            if quote:
                buf.append(ch)
            esc = True
            continue
        if quote:
            if ch == quote:
                quote = None
                args.append("".join(buf)); buf = []; started = False
            else:
                buf.append(ch)
            continue
        if ch in "'\"":
            quote = ch; started = True; continue
        if ch == "," or ch.isspace():
            continue
        # argument non quote (tolerance)
        buf.append(ch); started = True
    if started and buf:
        args.append("".join(buf))
    return args


def parse_bare_args(inner):
    """Arguments d'un ##+js(...) uBO: virgules non echappees, sans quotes."""
    args, buf, esc = [], [], False
    for ch in inner:
        if esc:
            buf.append(ch); esc = False; continue
        if ch == "\\":
            esc = True; buf.append(ch); continue
        if ch == ",":
            args.append("".join(buf).strip()); buf = []
            continue
        buf.append(ch)
    args.append("".join(buf).strip())
    return [a for a in args if a != ""] or [""]


class Converter(object):

    def __init__(self, legacy=False, document_policy="guard", allow_has=False,
                 css_group_size=250, keep_extended=True):
        self.legacy = legacy
        self.types_map = RESOURCE_TYPES_LEGACY if legacy else RESOURCE_TYPES_MODERN
        self.all_types = ALL_TYPES_LEGACY if legacy else ALL_TYPES_MODERN
        if legacy and document_policy == "guard":
            document_policy = "enumerate"
        self.document_policy = document_policy
        self.allow_has = allow_has
        self.css_group_size = css_group_size
        self.keep_extended = keep_extended
        self.reset()

    def reset(self):
        self.blocks = []            # blocages "sous-ressource"
        self.doc_blocks = []        # blocages visant explicitement le document
        self.cookie_rules = []
        self.css = {}               # trigger_key -> {"trigger":..., "selectors":[...]}
        self.exceptions = []
        self.doc_exceptions = []
        self.skipped = {}
        self.notes = {}
        self.counts = {"total": 0, "comments": 0, "converted": 0, "skipped": 0}
        self.extended = {"scriptlets": [], "procedural": [], "styles": [],
                         "html": [], "raw_js": 0}
        self._css_exceptions = {}
        self._badfilters = set()
        self._seen = set()

    # -- comptabilite ------------------------------------------------------- #

    def skip(self, reason):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        self.counts["skipped"] += 1

    def note(self, reason):
        self.notes[reason] = self.notes.get(reason, 0) + 1

    # -- passe 1a: retractations $badfilter --------------------------------- #

    def collect_badfilters(self, lines):
        """`regle$badfilter` annule la regle identique declaree ailleurs.

        C'est une retractation explicite du mainteneur: l'ignorer reviendrait a
        bloquer ce que la liste amont a desavoue.
        """
        for raw in lines:
            line = raw.strip()
            if not line or line[0] in "!#[" or "badfilter" not in line:
                continue
            try:
                self._badfilters.add(rule_key(line, drop="badfilter"))
            except Exception:  # noqa: BLE001
                continue

    # -- passe 1b: exceptions cosmetiques ----------------------------------- #

    def collect_css_exceptions(self, lines):
        for line in lines:
            line = line.strip()
            if not line or line[0] in "!#[":
                if not line.startswith("#@#"):
                    continue
            parsed = self.split_cosmetic(line)
            if not parsed:
                continue
            domains, marker, body = parsed
            if marker != "#@#":
                continue
            inc, _, _ = parse_domain_option(domains.replace(",", "|"))
            self._css_exceptions.setdefault(body.strip(), set()).update(inc)

    # -- decoupage cosmetique ----------------------------------------------- #

    @staticmethod
    def split_cosmetic(line):
        best = None
        for marker in COSMETIC_MARKERS:
            pos = line.find(marker)
            if pos == -1:
                continue
            if best is None or pos < best[0] or (pos == best[0] and len(marker) > len(best[1])):
                best = (pos, marker)
        if best is None:
            return None
        pos, marker = best
        domains = line[:pos]
        body = line[pos + len(marker):]
        if not body:
            return None
        # Le champ domaines d'une regle cosmetique ne contient jamais / $ ou espace.
        if re.search(r"[/$\s\"']", domains):
            return None
        return domains, marker, body

    # -- validation d'un selecteur CSS -------------------------------------- #

    def valid_selector(self, sel):
        sel = sel.strip()
        if not sel or len(sel) > 1024:
            raise Unsupported("selecteur CSS vide ou trop long")
        if "{" in sel or "}" in sel:
            raise Unsupported("injection de style (non supportee)")
        low = sel.lower()
        for token in EXTENDED_CSS_TOKENS:
            if token in low:
                raise Unsupported("pseudo-classe CSS etendue")
        if ":has(" in low and not self.allow_has:
            raise Unsupported("pseudo-classe :has() (desactivee par --no-has)")
        if any(ord(c) < 32 for c in sel):
            raise Unsupported("caractere de controle dans le selecteur")
        return sel

    # -- ajout d'une regle -------------------------------------------------- #

    VALID_TRIGGER_KEYS = frozenset((
        "url-filter", "url-filter-is-case-sensitive", "if-domain", "unless-domain",
        "if-top-url", "unless-top-url", "resource-type", "load-type", "load-context"))
    CONDITION_KEYS = ("if-domain", "unless-domain", "if-top-url", "unless-top-url")
    VALID_ACTIONS = frozenset((
        "block", "block-cookies", "css-display-none", "ignore-previous-rules",
        "make-https"))

    def validate(self, trigger, action):
        """Dernier filet: rejette tout ce que WebKit refuserait a la compilation."""
        extra = set(trigger) - self.VALID_TRIGGER_KEYS
        if extra:
            raise Unsupported("cle de trigger invalide: %s" % ",".join(sorted(extra)))
        uf = trigger.get("url-filter")
        if not isinstance(uf, str) or not uf:
            raise Unsupported("url-filter manquant")
        if any(ord(c) > 127 for c in uf):
            raise Unsupported("url-filter non-ASCII")
        if any(tok in uf for tok in BAD_REGEX_TOKENS):
            raise Unsupported("regex hors du sous-ensemble WebKit")
        if misplaced_anchor(uf):
            raise Unsupported("ancre `^` ou `$` mal placee")
        # WebKit: "A trigger cannot have more than one condition
        # (if-domain, unless-domain, if-top-url, or unless-top-url)".
        present = [k for k in self.CONDITION_KEYS if k in trigger]
        if len(present) > 1:
            raise Unsupported("conditions multiples: %s" % ",".join(present))
        for key in present:
            if not trigger[key]:
                raise Unsupported("condition %s vide" % key)
        for key in ("if-domain", "unless-domain"):
            for dom in trigger.get(key, []):
                if dom != dom.lower() or any(ord(c) > 127 for c in dom):
                    raise Unsupported("domaine non normalise")
        for key in ("if-top-url", "unless-top-url"):
            for rx in trigger.get(key, []):
                if (not rx or any(ord(c) > 127 for c in rx)
                        or any(tok in rx for tok in BAD_REGEX_TOKENS)
                        or misplaced_anchor(rx)):
                    raise Unsupported("regex %s hors sous-ensemble WebKit" % key)
        if set(trigger.get("resource-type", [])) - set(self.all_types):
            raise Unsupported("resource-type hors profil")
        if set(trigger.get("load-type", [])) - {"first-party", "third-party"}:
            raise Unsupported("load-type invalide")
        if set(trigger.get("load-context", [])) - {"top-frame", "child-frame"}:
            raise Unsupported("load-context invalide")
        if action.get("type") not in self.VALID_ACTIONS:
            raise Unsupported("action invalide")

    def emit(self, bucket, trigger, action):
        self.validate(trigger, action)
        rule = {"trigger": trigger, "action": action}
        key = json.dumps(rule, sort_keys=True, separators=(",", ":"))
        if key in self._seen:
            self.note("doublon fusionne")
            return
        self._seen.add(key)
        bucket.append(rule)
        self.counts["converted"] += 1

    # -- regles reseau ------------------------------------------------------ #

    def convert_network(self, line):
        exception = line.startswith("@@")
        if exception:
            line = line[2:]

        pattern, opts = split_options(line)
        mods = split_modifiers(opts) if opts else []

        inc_types, exc_types = [], []
        if_dom, unless_dom = [], []
        load_type = None
        case_sensitive = False
        document_intent = False
        child_frame_only = False
        cookie_only = False
        elemhide_exception = False

        for mod in mods:
            neg = mod.startswith("~")
            name = mod[1:] if neg else mod
            value = ""
            if "=" in name:
                name, value = name.split("=", 1)
            name = MODIFIER_ALIASES.get(name.strip().lower(), name.strip().lower())

            if name == "domain":
                inc, exc, dropped = parse_domain_option(value)
                if dropped and not inc and not exc:
                    # Ex. $domain=/regex/ : la portee est inexprimable. Garder la
                    # regle l'appliquerait partout au lieu d'un seul site.
                    raise Unsupported("$domain inexprimable (regex ou joker)")
                if dropped:
                    self.note("domaine ignore (joker ou regex dans $domain)")
                if_dom.extend(inc)
                unless_dom.extend(exc)
            elif name == "third-party":
                load_type = "first-party" if neg else "third-party"
            elif name == "first-party":
                load_type = "third-party" if neg else "first-party"
            elif name == "match-case":
                case_sensitive = not neg
            elif name == "cookie":
                if value or exception:
                    raise Unsupported("$cookie avec valeur / en exception")
                cookie_only = True
            elif name == "document":
                document_intent = True
                (exc_types if neg else inc_types).append("document")
            elif name == "subdocument":
                if neg:
                    exc_types.append("subdocument")
                else:
                    inc_types.append("subdocument")
                    child_frame_only = True
            elif name in ("elemhide", "generichide", "specifichide", "content",
                          "jsinject", "urlblock", "extension") and exception:
                elemhide_exception = True
            elif name in self.types_map:
                (exc_types if neg else inc_types).append(name)
            elif name in IGNORED_MODIFIERS:
                self.note("modificateur sans effet sous WebKit: $%s" % name)
            elif name == "badfilter":
                raise Unsupported("directive $badfilter (retractation appliquee)")
            elif name in UNSUPPORTED_MODIFIERS:
                raise Unsupported("modificateur non supporte: $%s" % name)
            else:
                raise Unsupported("modificateur inconnu: $%s" % name)

        # En syntaxe adblock, `@@...$document` desactive le filtrage sur toute
        # la page, pas seulement sur la requete du document.
        if exception and (elemhide_exception or inc_types == ["document"]):
            elemhide_exception = True
            inc_types = [t for t in inc_types if t != "document"]

        url_filters = pattern_to_url_filter(pattern)

        trigger = {"url-filter": url_filters[0]}
        if case_sensitive:
            trigger["url-filter-is-case-sensitive"] = True

        resource = []
        if inc_types:
            for t in inc_types:
                for wt in self.types_map[t]:
                    if wt not in resource:
                        resource.append(wt)
        elif exc_types:
            excluded = set()
            for t in exc_types:
                excluded.update(self.types_map[t])
            if self.document_policy == "enumerate" and not exception:
                excluded.add("document")
            resource = [t for t in self.all_types if t not in excluded]
            if not resource:
                raise Unsupported("tous les types de ressource sont exclus")
        elif self.document_policy == "enumerate" and not exception:
            resource = [t for t in self.all_types if t != "document"]

        if resource:
            trigger["resource-type"] = resource
        if child_frame_only and not self.legacy and inc_types == ["subdocument"]:
            trigger["load-context"] = ["child-frame"]
        if load_type:
            trigger["load-type"] = [load_type]

        if if_dom and unless_dom:
            raise Unsupported("$domain melange inclusions et exclusions")
        if if_dom:
            trigger["if-domain"] = sorted(set(if_dom))
        elif unless_dom:
            trigger["unless-domain"] = sorted(set(unless_dom))

        def emit_all(bucket, action):
            """Une alternation eclatee donne N regles au trigger identique."""
            for uf in url_filters:
                t = dict(trigger)
                t["url-filter"] = uf
                self.emit(bucket, t, dict(action))
            if len(url_filters) > 1:
                self.note("alternation eclatee en %d regles" % len(url_filters))

        if exception:
            if elemhide_exception or (document_intent and not inc_types):
                # Exception de page entiere. WebKit n'accepte qu'une seule
                # condition par trigger: on choisit la plus specifique.
                top = {"url-filter": ".*"}
                if url_filters != [".*"]:
                    top["if-top-url"] = url_filters
                    if if_dom or unless_dom:
                        self.note("$domain abandonne (une seule condition par trigger)")
                elif if_dom:
                    top["if-domain"] = trigger["if-domain"]
                elif unless_dom:
                    top["unless-domain"] = trigger["unless-domain"]
                else:
                    raise Unsupported("exception globale sans portee")
                self.emit(self.doc_exceptions, top,
                          {"type": "ignore-previous-rules"})
            else:
                emit_all(self.exceptions, {"type": "ignore-previous-rules"})
            return

        if cookie_only:
            emit_all(self.cookie_rules, {"type": "block-cookies"})
            return

        emit_all(self.doc_blocks if document_intent else self.blocks,
                 {"type": "block"})

    # -- regles cosmetiques ------------------------------------------------- #

    def capture_extended(self, domains, marker, body):
        """Consigne une regle non convertible en WebKit mais exploitable par un
        moteur a injection (extension). Ne modifie pas le comptage: la regle
        reste ecartee de la sortie WebKit."""
        if not self.keep_extended:
            return
        inc, exc, _ = parse_domain_option(domains.replace(",", "|"))
        scope = {"domains": sorted(set(d[1:] for d in inc)),
                 "excluded": sorted(set(d[1:] for d in exc))}
        exception = "@" in marker

        m = SCRIPTLET_AG.match(body.strip())
        if marker in ("#%#", "#@%#") and m:
            args = parse_quoted_args(m.group(1))
            if args:
                self.extended["scriptlets"].append(dict(
                    scope, name=args[0], args=args[1:],
                    syntax="adguard", exception=exception))
            return
        if marker in ("#%#", "#@%#"):
            self.extended["raw_js"] += 1     # JS libre: non reutilisable tel quel
            return

        m = SCRIPTLET_UBO.match(body.strip())
        if m:
            args = parse_bare_args(m.group(1))
            if args and args[0]:
                self.extended["scriptlets"].append(dict(
                    scope, name=args[0], args=args[1:],
                    syntax="ubo", exception=exception))
            return

        if body.startswith("^"):
            self.extended["html"].append(dict(scope, expression=body[1:],
                                              exception=exception))
            return

        if marker in ("#$#", "#$?#", "#@$#", "#@$?#"):
            if "{" in body and body.rstrip().endswith("}"):
                sel, decl = body.split("{", 1)
                self.extended["styles"].append(dict(
                    scope, selector=sel.strip(),
                    declarations=decl.rstrip().rstrip("}").strip(),
                    extended=("?" in marker), exception=exception))
            else:
                self.extended["raw_js"] += 1
            return

        if marker in ("#?#", "#@?#") or marker == "##":
            self.extended["procedural"].append(dict(
                scope, selector=body.strip(), exception=exception))

    def convert_cosmetic(self, domains, marker, body):
        if marker != "##":
            self.capture_extended(domains, marker, body)
            raise Unsupported({
                "#@#": "exception cosmetique (traitee en amont)",
                "#?#": "selecteur CSS etendu (#?#)",
                "#@?#": "selecteur CSS etendu (#@?#)",
                "#$#": "injection de style / scriptlet (#$#)",
                "#$?#": "injection de style etendue (#$?#)",
                "#@$#": "exception d'injection de style",
                "#@$?#": "exception d'injection de style etendue",
                "#%#": "JavaScript / scriptlet (#%#)",
                "#@%#": "exception de scriptlet",
            }.get(marker, "syntaxe cosmetique non supportee"))

        if body.startswith("+js(") or body.startswith("^"):
            self.capture_extended(domains, marker, body)
            raise Unsupported("scriptlet ou filtrage HTML")

        try:
            selector = self.valid_selector(body)
        except Unsupported:
            self.capture_extended(domains, marker, body)
            raise
        inc, exc, dropped = parse_domain_option(domains.replace(",", "|"))
        if dropped:
            self.note("domaine ignore (joker) dans une regle cosmetique")
            if domains and not inc and not exc:
                raise Unsupported("domaine cosmetique non exprimable (joker de TLD)")

        excepted = self._css_exceptions.get(selector, set())
        if excepted:
            if inc:
                inc = [d for d in inc if d not in excepted]
                if not inc:
                    raise Unsupported("regle cosmetique entierement exceptee")
            else:
                exc = sorted(set(exc) | excepted)

        trigger = {"url-filter": ".*"}
        if inc and exc:
            # WebKit interdit if-domain et unless-domain simultanement.
            trigger["if-domain"] = sorted(set(inc))
            self.note("unless-domain abandonne (incompatible avec if-domain)")
        elif inc:
            trigger["if-domain"] = sorted(set(inc))
        elif exc:
            trigger["unless-domain"] = sorted(set(exc))

        key = json.dumps(trigger, sort_keys=True, separators=(",", ":"))
        slot = self.css.setdefault(key, {"trigger": trigger, "selectors": []})
        if selector not in slot["selectors"]:
            slot["selectors"].append(selector)
            self.counts["converted"] += 1
        else:
            self.note("doublon fusionne")

    # -- boucle principale -------------------------------------------------- #

    def convert_lines(self, lines, hosts_mode=False):
        self.collect_badfilters(lines)
        self.collect_css_exceptions(lines)

        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            if line[0] in "!" or line.startswith("[Adblock"):
                self.counts["comments"] += 1
                continue

            if hosts_mode:
                if line[0] == "#":
                    self.counts["comments"] += 1
                    continue
                m = HOSTS_LINE.match(line)
                if m:
                    host = m.group(1).lower()
                    if host in ("localhost", "localhost.localdomain", "broadcasthost",
                                "local", "0.0.0.0", "ip6-localhost", "ip6-loopback"):
                        continue
                    line = "||%s^" % host
                elif DOMAIN_OK.match(line.lower()):
                    line = "||%s^" % line.lower()
                else:
                    self.counts["comments"] += 1
                    continue

            self.counts["total"] += 1
            try:
                cosmetic = self.split_cosmetic(line)
                if cosmetic:
                    domains, marker, body = cosmetic
                    if marker == "#@#":
                        continue  # deja pris en compte en passe 1
                    self.convert_cosmetic(domains, marker, body)
                else:
                    if line.startswith("#"):
                        self.counts["comments"] += 1
                        self.counts["total"] -= 1
                        continue
                    if self._badfilters and rule_key(line) in self._badfilters:
                        self.skip("retiree par $badfilter (retractation amont)")
                        continue
                    self.convert_network(line)
            except Unsupported as e:
                self.skip(str(e))
            except Exception as e:  # noqa: BLE001
                self.skip("erreur de parsing (%s)" % type(e).__name__)

    # -- assemblage --------------------------------------------------------- #

    def build_css_rules(self):
        rules = []
        for slot in self.css.values():
            sels = slot["selectors"]
            for i in range(0, len(sels), self.css_group_size):
                chunk = sels[i:i + self.css_group_size]
                rules.append({
                    "trigger": slot["trigger"],
                    "action": {"type": "css-display-none",
                               "selector": ", ".join(chunk)},
                })
        return rules

    def document_guard(self):
        """Empeche les regles generiques de bloquer la navigation principale.

        En adblock, `||exemple.com^` ne bloque pas le chargement de la page
        elle-meme; sous WebKit, un trigger sans resource-type couvre `document`.
        Une seule regle ignore-previous-rules ciblant le document de premier
        niveau retablit la semantique attendue sans gonfler chaque regle.
        """
        return {
            "trigger": {"url-filter": ".*", "resource-type": ["document"],
                        "load-context": ["top-frame"]},
            "action": {"type": "ignore-previous-rules"},
        }

    def assemble(self):
        """Ordre = semantique: WebKit applique les regles dans l'ordre du tableau."""
        out = list(self.blocks)
        if self.document_policy == "guard" and out:
            out.append(self.document_guard())
        out.extend(self.doc_blocks)
        out.extend(self.cookie_rules)
        out.extend(self.build_css_rules())
        tail = list(self.exceptions) + list(self.doc_exceptions)
        return out, tail


# --------------------------------------------------------------------------- #
# Entrees / sorties
# --------------------------------------------------------------------------- #

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def detect_hosts(lines):
    checked = hits = 0
    for line in lines:
        s = line.strip()
        if not s or s[0] in "!#":
            continue
        checked += 1
        if HOSTS_LINE.match(s):
            hits += 1
        if checked >= 300:
            break
    return checked > 0 and hits / float(checked) >= 0.6


def read_index(in_dir):
    path = os.path.join(in_dir, "index.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return {v.get("file"): v for v in data.get("lists", {}).values() if v.get("file")}
    except Exception:  # noqa: BLE001
        return {}


def write_json(path, rules, pretty):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        if pretty:
            json.dump(rules, fh, indent=1, ensure_ascii=False)
        else:
            json.dump(rules, fh, separators=(",", ":"), ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)


def convert_file(path, meta, args):
    base = os.path.splitext(os.path.basename(path))[0]
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    fmt = (meta or {}).get("format", "adblock")
    hosts_mode = fmt == "hosts" or detect_hosts(lines)

    conv = Converter(legacy=args.legacy, document_policy=args.document_policy,
                     allow_has=args.allow_has, css_group_size=args.css_group_size,
                     keep_extended=args.extended)
    conv.convert_lines(lines, hosts_mode=hosts_mode)
    body, tail = conv.assemble()

    total = len(body) + len(tail)
    outputs = []

    if total == 0:
        chunks = []
    elif total <= args.max_rules:
        chunks = [body + tail]
    else:
        # On duplique les exceptions dans chaque fichier: `ignore-previous-rules`
        # n'agit qu'a l'interieur d'un meme content blocker compile.
        room = args.max_rules - len(tail)
        if room < 1000:
            raise RuntimeError("trop d'exceptions pour decouper (%d)" % len(tail))
        chunks = [body[i:i + room] + tail for i in range(0, len(body), room)]

    for idx, chunk in enumerate(chunks, 1):
        name = PREFIX + base + (".json" if len(chunks) == 1 else "-%d.json" % idx)
        out_path = os.path.join(args.out, name)
        if not args.dry_run:
            write_json(out_path, chunk, args.pretty)
        outputs.append({"file": name, "rules": len(chunk),
                        "bytes": os.path.getsize(out_path) if not args.dry_run else 0})

    ext = conv.extended
    ext_counts = {k: (v if isinstance(v, int) else len(v)) for k, v in ext.items()}
    ext_total = sum(v for k, v in ext_counts.items() if k != "raw_js")
    ext_file = None
    if args.extended and ext_total and not args.dry_run:
        ext_file = EXT_PREFIX + base + ".json"
        payload = {
            "source_file": os.path.basename(path),
            "name": (meta or {}).get("name", base),
            "version": (meta or {}).get("version", ""),
            "generated_at": now_iso(),
            "note": ("Regles non exprimables en Content Blocker WebKit mais "
                     "exploitables par un moteur a injection (Safari Web "
                     "Extension). Non chargeables telles quelles par Safari."),
            "counts": ext_counts,
            "scriptlets": ext["scriptlets"],
            "procedural": ext["procedural"],
            "styles": ext["styles"],
            "html": ext["html"],
        }
        with open(os.path.join(args.extended_out, ext_file), "w",
                  encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)
            fh.write("\n")

    report = {
        "source_file": os.path.basename(path),
        "source_name": (meta or {}).get("name", base),
        "source_title": (meta or {}).get("title", ""),
        "source_version": (meta or {}).get("version", ""),
        "source_url": (meta or {}).get("url", ""),
        "format": "hosts" if hosts_mode else "adblock",
        "converted_at": now_iso(),
        "profile": "legacy" if args.legacy else "modern (Safari 15+)",
        "document_policy": conv.document_policy,
        "lines_total": len(lines),
        "rules_in": conv.counts["total"],
        "rules_out": total,
        "coverage_pct": round(100.0 * conv.counts["converted"] / conv.counts["total"], 2)
                        if conv.counts["total"] else 0.0,
        "breakdown": {
            "block": len(conv.blocks),
            "block_document": len(conv.doc_blocks),
            "block_cookies": len(conv.cookie_rules),
            "css_display_none": len(conv.build_css_rules()),
            "css_selectors": sum(len(s["selectors"]) for s in conv.css.values()),
            "ignore_previous_rules": len(tail),
        },
        "skipped_total": conv.counts["skipped"],
        "skipped_reasons": dict(sorted(conv.skipped.items(),
                                       key=lambda kv: -kv[1])),
        "notes": dict(sorted(conv.notes.items(), key=lambda kv: -kv[1])),
        "outputs": outputs,
        "extended": {"file": ext_file, "total": ext_total, "counts": ext_counts},
    }
    return report


def main():
    ap = argparse.ArgumentParser(
        description="Convertit les listes adblock en Content Blocker JSON WebKit.")
    ap.add_argument("--in", dest="in_dir", default=DEFAULT_IN,
                    help="dossier des listes brutes (defaut: filters/)")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="dossier de sortie (defaut: webkit-rules/)")
    ap.add_argument("--reports", default=DEFAULT_REPORTS, help="dossier des rapports")
    ap.add_argument("--extended-out", default=DEFAULT_EXTENDED,
                    help="dossier des regles a injection (defaut: extended-rules/)")
    ap.add_argument("--no-extended", dest="extended", action="store_false", default=True,
                    help="ne pas produire les fichiers Extended-*.json")
    ap.add_argument("--only", nargs="+", metavar="MOTIF",
                    help="ne convertir que les fichiers dont le nom contient ces motifs")
    ap.add_argument("--legacy", action="store_true",
                    help="profil WebKit classique (pas de fetch/websocket/ping/load-context)")
    ap.add_argument("--document-policy", choices=["guard", "enumerate", "allow"],
                    default="guard",
                    help="protection de la navigation principale (defaut: guard)")
    ap.add_argument("--no-has", dest="allow_has", action="store_false", default=True,
                    help=":has() est accepte par defaut (verifie sur le compilateur "
                         "WebKit); ce drapeau le desactive pour viser Safari < 16.4")
    ap.add_argument("--css-group-size", type=int, default=250,
                    help="selecteurs regroupes par regle css-display-none")
    ap.add_argument("--max-rules", type=int, default=WEBKIT_MAX_RULES,
                    help="regles max par fichier avant decoupage (defaut: 150000)")
    ap.add_argument("--pretty", action="store_true", help="JSON indente")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.in_dir, "*.txt")))
    if args.only:
        needles = [n.lower() for n in args.only]
        files = [f for f in files
                 if any(n in os.path.basename(f).lower() for n in needles)]
    if not files:
        print("Aucune liste dans %s (lancer fetch_filters.py d'abord)." % args.in_dir,
              file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.reports, exist_ok=True)
    if args.extended:
        os.makedirs(args.extended_out, exist_ok=True)
    index_meta = read_index(args.in_dir)

    reports = []
    for path in files:
        meta = index_meta.get(os.path.basename(path), {})
        try:
            rep = convert_file(path, meta, args)
        except Exception as e:  # noqa: BLE001
            print("  x %-46s %s" % (os.path.basename(path)[:46], e), file=sys.stderr)
            continue
        reports.append(rep)
        if not args.dry_run:
            rp = os.path.join(args.reports,
                              os.path.splitext(os.path.basename(path))[0] + ".report.json")
            with open(rp, "w", encoding="utf-8") as fh:
                json.dump(rep, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        if not args.quiet:
            print("  + %-44s %7d -> %7d regles (%5.1f%%) %s" % (
                rep["source_file"][:44], rep["rules_in"], rep["rules_out"],
                rep["coverage_pct"],
                "" if len(rep["outputs"]) == 1 else "[%d fichiers]" % len(rep["outputs"])))

    if not reports:
        return 1

    catalog = {
        "generated_at": now_iso(),
        "generator": "convert_webkit.py",
        "profile": reports[0]["profile"],
        "totals": {
            "lists": len(reports),
            "files": sum(len(r["outputs"]) for r in reports),
            "rules_in": sum(r["rules_in"] for r in reports),
            "rules_out": sum(r["rules_out"] for r in reports),
            "skipped": sum(r["skipped_total"] for r in reports),
            "extended": sum(r["extended"]["total"] for r in reports),
        },
        "lists": [{
            "name": r["source_name"],
            "source": r["source_file"],
            "version": r["source_version"],
            "coverage_pct": r["coverage_pct"],
            "files": r["outputs"],
            "extended_file": r["extended"]["file"],
        } for r in reports],
    }
    # Purge des fichiers d'une execution precedente qui n'ont plus de source
    # (liste retiree du catalogue, ou decoupage devenu plus court). Un fichier
    # orphelin ferait echouer la verification et resterait charge cote Safari.
    # La purge n'a de sens que sur un run complet: avec --only, les fichiers
    # des autres listes sont legitimement absents de `reports`.
    full_run = not args.only
    if args.extended and full_run and not args.dry_run:
        keep_ext = {r["extended"]["file"] for r in reports if r["extended"]["file"]}
        for f in os.listdir(args.extended_out):
            if f.startswith(EXT_PREFIX) and f.endswith(".json") and f not in keep_ext:
                os.remove(os.path.join(args.extended_out, f))

    produced = {o["file"] for r in reports for o in r["outputs"]}
    stale = [f for f in os.listdir(args.out)
             if f.startswith(PREFIX) and f.endswith(".json") and f not in produced]
    if stale and full_run and not args.dry_run:
        for f in stale:
            os.remove(os.path.join(args.out, f))
        print("  purge: %d fichier(s) obsolete(s) supprime(s)" % len(stale))

    if not args.dry_run:
        write_json_obj = os.path.join(args.out, "index.json")
        with open(write_json_obj, "w", encoding="utf-8") as fh:
            json.dump(catalog, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        write_markdown_report(os.path.join(args.reports, "CONVERSION.md"), catalog, reports)

    t = catalog["totals"]
    print("\n%s" % ("-" * 60))
    print("%d listes -> %d fichiers WebKit | %d regles retenues / %d entrees | %d ecartees"
          % (t["lists"], t["files"], t["rules_out"], t["rules_in"], t["skipped"]))
    if t.get("extended"):
        print("%d regles a injection consignees dans %s"
              % (t["extended"], args.extended_out))
    return 0


def write_markdown_report(path, catalog, reports):
    agg = {}
    for r in reports:
        for k, v in r["skipped_reasons"].items():
            agg[k] = agg.get(k, 0) + v
    lines = [
        "# Rapport de conversion WebKit", "",
        "Genere le %s — profil %s." % (catalog["generated_at"], catalog["profile"]), "",
        "| Liste | Version | Entrees | Regles WebKit | Couverture | Fichiers |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in sorted(reports, key=lambda x: -x["rules_out"]):
        lines.append("| %s | %s | %d | %d | %.1f%% | %d |" % (
            r["source_name"], r["source_version"] or "-", r["rules_in"],
            r["rules_out"], r["coverage_pct"], len(r["outputs"])))
    lines += ["", "## Motifs d'exclusion (tous listes confondues)", "",
              "| Motif | Occurrences |", "|---|---:|"]
    for reason, n in sorted(agg.items(), key=lambda kv: -kv[1])[:40]:
        lines.append("| %s | %d |" % (reason, n))
    lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
