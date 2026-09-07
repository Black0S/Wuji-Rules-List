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
PREFIX = "Webkit-"

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
    ":if(", ":if-not(", ":properties(", ":others(", ":not(:has", "##^",
)

# Constructions regex hors du sous-ensemble accepte par WebKit.
BAD_REGEX_TOKENS = ("{", "}", "(?", "\\d", "\\w", "\\s", "\\D", "\\W", "\\S",
                    "\\b", "\\B", "*?", "+?", "??", "|", "\\1", "\\2", "\\3")

COSMETIC_MARKERS = ["#@$?#", "#@$#", "#@?#", "#@%#", "#@#",
                    "#$?#", "#$#", "#?#", "#%#", "##"]

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


def validate_raw_regex(rx):
    if not rx:
        raise Unsupported("regex vide")
    if any(t in rx for t in BAD_REGEX_TOKENS):
        raise Unsupported("regex hors du sous-ensemble WebKit")
    if any(ord(c) > 127 for c in rx):
        raise Unsupported("regex non-ASCII")
    try:
        re.compile(rx)
    except re.error:
        raise Unsupported("regex invalide")
    return rx


def pattern_to_url_filter(pattern):
    """Traduit un motif adblock en `url-filter` WebKit. Leve Unsupported."""
    pattern = pattern.strip()
    if not pattern or pattern in ("*", "||", "|"):
        return ".*"

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
        return ".*"
    try:
        re.compile(rx)
    except re.error:
        raise Unsupported("regex generee invalide")
    return rx


# --------------------------------------------------------------------------- #
# Parsing des modificateurs
# --------------------------------------------------------------------------- #

def split_options(text):
    """Separe `pattern$opt1,opt2`. Gere les motifs regex `/.../$opts`."""
    if text.startswith("/"):
        close = text.rfind("/")
        if close > 0:
            tail = text[close + 1:]
            if tail.startswith("$"):
                return text[:close + 1], tail[1:]
            if tail == "":
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


def normalize_domain(d):
    """Retourne le domaine WebKit (`*d` = domaine + sous-domaines) ou None."""
    d = d.strip().lower().rstrip(".")
    if not d or d.startswith("/") or "*" in d or "~" in d[1:]:
        return None
    if any(ord(c) > 127 for c in d):
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:  # noqa: BLE001
            return None
    if not DOMAIN_OK.match(d):
        return None
    return "*" + d


def parse_domain_option(value):
    """`a.com|~b.com` -> (inclus, exclus, nb_ignores)."""
    inc, exc, dropped = [], [], 0
    for raw in value.split("|"):
        raw = raw.strip()
        if not raw:
            continue
        neg = raw.startswith("~")
        dom = normalize_domain(raw[1:] if neg else raw)
        if dom is None:
            dropped += 1
            continue
        (exc if neg else inc).append(dom)
    return inc, exc, dropped


# --------------------------------------------------------------------------- #
# Convertisseur
# --------------------------------------------------------------------------- #

class Converter(object):

    def __init__(self, legacy=False, document_policy="guard", allow_has=False,
                 css_group_size=250):
        self.legacy = legacy
        self.types_map = RESOURCE_TYPES_LEGACY if legacy else RESOURCE_TYPES_MODERN
        self.all_types = ALL_TYPES_LEGACY if legacy else ALL_TYPES_MODERN
        if legacy and document_policy == "guard":
            document_policy = "enumerate"
        self.document_policy = document_policy
        self.allow_has = allow_has
        self.css_group_size = css_group_size
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
        self._css_exceptions = {}
        self._seen = set()

    # -- comptabilite ------------------------------------------------------- #

    def skip(self, reason):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        self.counts["skipped"] += 1

    def note(self, reason):
        self.notes[reason] = self.notes.get(reason, 0) + 1

    # -- passe 1: exceptions cosmetiques ------------------------------------ #

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
            raise Unsupported("pseudo-classe :has() (activer --allow-has)")
        if any(ord(c) < 32 for c in sel):
            raise Unsupported("caractere de controle dans le selecteur")
        return sel

    # -- ajout d'une regle -------------------------------------------------- #

    VALID_TRIGGER_KEYS = frozenset((
        "url-filter", "url-filter-is-case-sensitive", "if-domain", "unless-domain",
        "if-top-url", "unless-top-url", "resource-type", "load-type", "load-context"))
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
        if "if-domain" in trigger and "unless-domain" in trigger:
            raise Unsupported("if-domain et unless-domain simultanes")
        for key in ("if-domain", "unless-domain"):
            for dom in trigger.get(key, []):
                if dom != dom.lower() or any(ord(c) > 127 for c in dom):
                    raise Unsupported("domaine non normalise")
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
            elif name in UNSUPPORTED_MODIFIERS:
                raise Unsupported("modificateur non supporte: $%s" % name)
            else:
                raise Unsupported("modificateur inconnu: $%s" % name)

        # En syntaxe adblock, `@@...$document` desactive le filtrage sur toute
        # la page, pas seulement sur la requete du document.
        if exception and (elemhide_exception or inc_types == ["document"]):
            elemhide_exception = True
            inc_types = [t for t in inc_types if t != "document"]

        url_filter = pattern_to_url_filter(pattern)

        trigger = {"url-filter": url_filter}
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

        if exception:
            if elemhide_exception or (document_intent and not inc_types):
                # Exception de page entiere: on neutralise tout sur ce site.
                top = {"url-filter": ".*", "if-top-url": [url_filter]}
                if if_dom:
                    top["if-domain"] = trigger["if-domain"]
                self.emit(self.doc_exceptions, top,
                          {"type": "ignore-previous-rules"})
            else:
                self.emit(self.exceptions, trigger,
                          {"type": "ignore-previous-rules"})
            return

        if cookie_only:
            self.emit(self.cookie_rules, trigger, {"type": "block-cookies"})
            return

        bucket = self.doc_blocks if document_intent else self.blocks
        self.emit(bucket, trigger, {"type": "block"})

    # -- regles cosmetiques ------------------------------------------------- #

    def convert_cosmetic(self, domains, marker, body):
        if marker != "##":
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
            raise Unsupported("scriptlet ou filtrage HTML")

        selector = self.valid_selector(body)
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
                     allow_has=args.allow_has, css_group_size=args.css_group_size)
    conv.convert_lines(lines, hosts_mode=hosts_mode)
    body, tail = conv.assemble()

    total = len(body) + len(tail)
    outputs = []

    if total <= args.max_rules:
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
    ap.add_argument("--only", nargs="+", metavar="MOTIF",
                    help="ne convertir que les fichiers dont le nom contient ces motifs")
    ap.add_argument("--legacy", action="store_true",
                    help="profil WebKit classique (pas de fetch/websocket/ping/load-context)")
    ap.add_argument("--document-policy", choices=["guard", "enumerate", "allow"],
                    default="guard",
                    help="protection de la navigation principale (defaut: guard)")
    ap.add_argument("--allow-has", action="store_true",
                    help="autoriser :has() dans les selecteurs (Safari 16.4+)")
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
        },
        "lists": [{
            "name": r["source_name"],
            "source": r["source_file"],
            "version": r["source_version"],
            "coverage_pct": r["coverage_pct"],
            "files": r["outputs"],
        } for r in reports],
    }
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
