# -*- coding: utf-8 -*-
"""
extended_scope.py — la portee d'une regle etendue, telle que Wuji la lit.

Les annexes `Extended-*.json` ne passent pas par le compilateur de WebKit: c'est
le navigateur qui choisit, page par page, ce qu'il injecte. Rien n'oblige donc a
les plier aux limites du format WebKit — et les y plier coutait cher:

- `exemple.*` etait etendu vers une centaine de TLD choisis a la main: `.co.za`
  ou `.com.pk` n'y etaient pas, et chaque regle pesait cent domaines;
- `ru##.pub` perdait son unique domaine, faute de point: la regle devenait
  generique et s'appliquait a tous les sites du monde;
- `[$path=/x]`, `[$domain=/re/]` et `[$url=...]` etaient ignores ou perdus.

Ici chaque domaine est garde tel que la liste l'ecrit — hote, TLD, `nom.*` ou
`/regex/` — et une condition de page (`page`, regex JavaScript testee sur
`location.href`) porte le chemin ou l'URL. Une portee qu'on ne sait pas dire
fait ecarter la regle: jamais elle ne devient generique.
"""

import re

DOMAIN_OK = re.compile(r"^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*$")


class ScopeError(Exception):
    """Portee inexprimable: la regle est ecartee plutot qu'elargie."""


def _idna(name):
    if all(ord(c) < 128 for c in name):
        return name
    try:
        return name.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        return None


def extended_domain(raw):
    """`Exemple.COM` -> `exemple.com`; `nom.*` et `/re/` gardes tels quels.
    Rend None si la forme n'a pas de sens."""
    d = raw.strip()
    if d.endswith(">>"):          # uBO: le site et ses cadres
        d = d[:-2]
    if len(d) > 2 and d.startswith("/") and d.endswith("/"):
        try:
            re.compile(d[1:-1])
        except re.error:
            return None
        return d
    d = d.lower().rstrip(".")
    wild = d.endswith(".*")
    base = d[:-2] if wild else d
    base = _idna(base)
    if not base or "*" in base or not DOMAIN_OK.match(base):
        return None
    return base + ".*" if wild else base


def split_modifiers(opts):
    """Decoupe `a,b=/x{1,2}/,c` sur les virgules — pas celles d'une regex.

    Une valeur regex s'ouvre par `/` juste apres `=`, `|` ou `~`, et se ferme
    au `/` suivi d'une virgule, d'un `|` ou de la fin. Sans la fermeture, tout
    ce qui suivait une regex restait colle a elle: `$domain=/re/,script`
    perdait son `script`."""
    parts, buf, depth, in_re = [], [], 0, False
    i, n = 0, len(opts)
    while i < n:
        c = opts[i]
        if c == "\\":
            buf.append(opts[i:i + 2])
            i += 2
            continue
        if c == "/":
            if in_re and (i + 1 == n or opts[i + 1] in ",|"):
                in_re = False
            elif not in_re and (not buf or buf[-1] in ("=", "|", "~")):
                in_re = True
        elif not in_re and c == "(":
            depth += 1
        elif not in_re and c == ")":
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


def split_pipes(value):
    """`a.com|/(x|y)\\.com/|~b.com` -> les domaines, sans couper une regex."""
    out, buf, in_re, i = [], [], False, 0
    while i < len(value):
        c = value[i]
        if c == "\\":
            buf.append(value[i:i + 2])
            i += 2
            continue
        if c == "/":
            if in_re:
                in_re = False
            elif "".join(buf) in ("", "~"):
                in_re = True
        if c == "|" and not in_re:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return [d.strip() for d in out if d.strip()]


def pattern_to_js(pattern):
    """Motif adblock (`*`, `^`, `|`, `||`) -> regex JavaScript equivalente."""
    if len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
        return pattern[1:-1]
    out, i, n = [], 0, len(pattern)
    if pattern.startswith("||"):
        out.append(r"^[a-z][a-z0-9+.-]*://([^/?#]*\.)?"); i = 2
    elif pattern.startswith("|"):
        out.append("^"); i = 1
    end = pattern.endswith("|") and n > i
    if end:
        n -= 1
    for ch in pattern[i:n]:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(r"(?:[^\w.%-]|$)")
        elif ch in ".+?()[]{}|$\\/":
            out.append("\\" + ch)
        else:
            out.append(ch)
    if end:
        out.append("$")
    return "".join(out)


# `location.href` commence toujours par le schema et l'hote: une condition de
# chemin s'accroche juste apres.
HREF_HEAD = r"^[a-z][a-z0-9+.-]*://[^/?#]*"


def path_to_page(value):
    """`[$path=...]` -> regex sur `location.href`.

    AdGuard: sans valeur, la page d'accueil seule; `/re/`, une regex sur le
    chemin et la requete; sinon un motif qui commence au debut du chemin."""
    v = value.strip()
    if not v:
        return HREF_HEAD + r"/?(?:[?#]|$)"
    if len(v) > 2 and v.startswith("/") and v.endswith("/") and \
            re.search(r"[\\^$*+?()\[\]{}|]", v[1:-1]):
        inner = v[1:-1]
        if inner.startswith("^"):
            return HREF_HEAD + "(?:" + inner[1:] + ")"
        return HREF_HEAD + ".*(?:" + inner + ")"
    if not v.startswith("/"):
        # `[$path=page.html]`: le motif se trouve quelque part dans le chemin.
        return HREF_HEAD + "[^?#]*" + pattern_to_js(v)
    return HREF_HEAD + pattern_to_js("|" + v)[1:]


def scope(domains, prefix=""):
    """(`a.com,~b.a.com`, `$path=/x`) -> {"domains", "excluded"[, "page"]}.

    Leve ScopeError si une portee etait ecrite mais qu'aucun de ses domaines
    n'est lisible, ou si le prefixe porte un modificateur inconnu."""
    inc, exc, written = [], [], False
    raws = [r for r in domains.split(",") if r.strip()]
    page = None
    for mod in split_modifiers(prefix):
        name, eq, val = mod.partition("=")
        name = name.strip().lower()
        if name == "domain":
            raws.extend(split_pipes(val))
        elif name == "path":
            page = path_to_page(val if eq else "")
        elif name == "url":
            page = pattern_to_js(val.strip())
        else:
            raise ScopeError("modificateur cosmetique [$%s]" % name)
    for raw in raws:
        raw = raw.strip()
        neg = raw.startswith("~")
        d = extended_domain(raw[1:] if neg else raw)
        if not neg:
            written = True
        if d is None:
            continue
        (exc if neg else inc).append(d)
    if written and not inc:
        raise ScopeError("portee inexprimable (domaine illisible)")
    out = {"domains": sorted(set(inc)), "excluded": sorted(set(exc))}
    if page is not None:
        try:
            re.compile(page)
        except re.error:
            raise ScopeError("condition de page illisible")
        out["page"] = page
    return out


def split_style(body):
    """`sel { decl }` -> (sel, decl), l'accolade cherchee hors guillemets,
    crochets et parentheses — `[data-x="{a}"]` n'est pas une declaration.
    Rend None si le corps n'est pas une injection de style."""
    body = body.strip()
    if not body.endswith("}"):
        return None
    depth, quote, esc, start = 0, None, False, None
    for i, ch in enumerate(body):
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        elif ch == "{" and depth == 0:
            start = i
            break
    if start is None:
        return None
    sel, decl = body[:start].strip(), body[start + 1:-1].strip()
    if not sel or "{" in decl or "}" in decl:
        return None
    return sel, decl
