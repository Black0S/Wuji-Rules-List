#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_filters.py — Etape 1/2 du pipeline.

Decouvre et telecharge les listes de filtres adblock connues, en s'appuyant sur
le registre officiel AdGuard (qui reference aussi EasyList, EasyPrivacy, Fanboy,
uBlock Origin, Peter Lowe, etc.), plus les sources supplementaires declarees
dans sources.json.

Etat persistant dans <out>/index.json : ETag / Last-Modified / sha256, ce qui
permet des mises a jour incrementales (HTTP 304 = rien a retelecharger).

Exemples:
    python3 fetch_filters.py                      # tout le catalogue
    python3 fetch_filters.py --recommended        # uniquement les listes "recommended"
    python3 fetch_filters.py --only base,easylist # sous-ensemble par nom/id
    python3 fetch_filters.py --list               # affiche le catalogue sans rien telecharger
    python3 fetch_filters.py --force              # ignore le cache et l'expiration
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import urljoin
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SOURCES = os.path.join(ROOT, "sources.json")
DEFAULT_OUT = os.path.join(ROOT, "filters")
USER_AGENT = "Wuji-Rules-List/1.0 (+https://github.com/; filter list fetcher)"
INDEX_NAME = "index.json"


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(name):
    """'AdGuard Base filter' -> 'AdGuard-Base-filter' (conserve la casse)."""
    s = unicodedata.normalize("NFKD", name)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.replace("&", "and")
    s = re.sub(r"[^A-Za-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "list"


def log(msg, quiet=False):
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


def http_get(url, timeout=60, etag=None, last_modified=None, retries=3):
    """GET conditionnel. Retourne (status, body_bytes|None, headers)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, None, dict(e.headers or {})
            last_err = "HTTP %d" % e.code
            if e.code in (400, 401, 403, 404, 410):
                break  # inutile de reessayer
        except Exception as e:  # noqa: BLE001 - reseau: on veut tout capturer
            last_err = "%s: %s" % (type(e).__name__, e)
        if attempt < retries - 1:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(last_err or "echec inconnu")


def atomic_write_bytes(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


HEADER_RE = re.compile(r"^!\s*([A-Za-z][A-Za-z ]{1,24}?)\s*:\s*(.+?)\s*$")
INCLUDE_RE = re.compile(r"^!#include\s+(\S+)\s*$", re.I)
IF_RE = re.compile(r"^!#if\s+(.+?)\s*$", re.I)
ELSE_RE = re.compile(r"^!#else\s*$", re.I)
ENDIF_RE = re.compile(r"^!#endif\s*$", re.I)

# Environnement cible: un content blocker Safari. C'est ce que produit aussi
# AdGuard pour Safari, d'ou `adguard_ext_safari`. Toute autre capacite
# (scriptlets uBO, filtrage HTML, feuilles de style utilisateur) est absente.
PREPROC_TRUE = frozenset(("env_safari", "adguard_ext_safari", "adguard"))


def eval_preproc(expr, env=PREPROC_TRUE):
    """Evalue une condition `!#if` d'uBlock Origin: identifiants, ! && || ()."""
    tokens = re.findall(r"\(|\)|&&|\|\||!|[A-Za-z_][A-Za-z0-9_]*", expr)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def primary():
        t = take()
        if t == "!":
            return not primary()
        if t == "(":
            v = expression()
            if peek() == ")":
                take()
            return v
        if t is None:
            return False
        return t in env

    def conjunction():
        v = primary()
        while peek() == "&&":
            take()
            v = primary() and v
        return v

    def expression():
        v = conjunction()
        while peek() == "||":
            take()
            v = conjunction() or v
        return v

    try:
        return expression()
    except Exception:  # noqa: BLE001
        return True     # condition incomprise: on garde plutot que de perdre


def apply_preprocessor(text):
    """Ne conserve que les branches `!#if` valables pour la cible WebKit."""
    if "!#if" not in text:
        return text, 0
    out, stack, dropped = [], [], 0
    for line in text.splitlines():
        st = line.strip()
        m = IF_RE.match(st)
        if m:
            active = all(s[0] for s in stack) and eval_preproc(m.group(1))
            stack.append([eval_preproc(m.group(1)), active])
            continue
        if ELSE_RE.match(st) and stack:
            stack[-1][0] = not stack[-1][0]
            continue
        if ENDIF_RE.match(st) and stack:
            stack.pop()
            continue
        if all(s[0] for s in stack):
            out.append(line)
        else:
            if st and not st.startswith("!"):
                dropped += 1
    return "\n".join(out), dropped
PREPROC_RE = re.compile(r"^!#(if|else|endif|safari_cb_affinity)\b", re.I)


def resolve_includes(text, base_url, timeout, depth=0, seen=None, log_fn=None):
    """Assemble les listes-manifestes (`!#include chemin`) d'uBlock Origin.

    Sans cela, `uBlock filters - Annoyances` ou `RU AdList for uBO` arrivent
    vides: ce ne sont que des sommaires.
    """
    if "!#include" not in text:
        return text, 0
    if depth >= 5:
        return text, 0
    seen = seen if seen is not None else set()

    out, count = [], 0
    for line in text.splitlines():
        m = INCLUDE_RE.match(line.strip())
        if not m:
            out.append(line)
            continue
        target = urljoin(base_url, m.group(1))
        if target in seen:
            out.append("! [include ignore, cycle] " + m.group(1))
            continue
        seen.add(target)
        try:
            status, body, _ = http_get(target, timeout=timeout, retries=2)
            if status != 200 or not body:
                raise RuntimeError("status %s" % status)
            sub = body.decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            out.append("! [include echoue: %s] %s" % (e, m.group(1)))
            continue
        sub, nested = resolve_includes(sub, target, timeout, depth + 1, seen, log_fn)
        count += 1 + nested
        out.append("! >>> include: %s" % m.group(1))
        out.append(sub)
        out.append("! <<< fin include: %s" % m.group(1))
    return "\n".join(out), count


def parse_header(text, max_lines=60):
    """Extrait Title / Version / Expires / Homepage / License de l'en-tete."""
    meta = {}
    for i, line in enumerate(text.splitlines()):
        if i >= max_lines:
            break
        if not line.startswith("!"):
            if line.strip() and not line.startswith("["):
                break
            continue
        m = HEADER_RE.match(line)
        if m:
            key = m.group(1).strip().lower().replace(" ", "_")
            if key not in meta:
                meta[key] = m.group(2)
    return meta


def count_rules(text):
    """Compte les lignes utiles et les hache.

    Le hachage porte sur les seules regles: deux listes peuvent differer par
    leur en-tete tout en livrant exactement le meme contenu (ex. uBO
    annoyances.txt, simple enveloppe autour de annoyances-others.txt).
    """
    n = 0
    h = hashlib.sha256()
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "!#" or s.startswith("["):
            continue
        n += 1
        h.update(s.encode("utf-8"))
        h.update(b"\n")
    return n, h.hexdigest()


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #

def load_config(path):
    """Charge sources.json en signalant clairement une erreur de syntaxe.

    Le fichier est fait pour etre edite a la main: une virgule orpheline doit
    donner un message lisible, pas une trace Python.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        lines = raw.split("\n")
        lo, hi = max(0, e.lineno - 3), min(len(lines), e.lineno + 2)
        sys.stderr.write("\nErreur de syntaxe dans %s, ligne %d colonne %d : %s\n\n"
                         % (path, e.lineno, e.colno, e.msg))
        for i in range(lo, hi):
            mark = ">>" if i == e.lineno - 1 else "  "
            sys.stderr.write("%s %4d | %s\n" % (mark, i + 1, lines[i]))
        if "Expecting" in e.msg and e.lineno > 1:
            prev = lines[e.lineno - 2].rstrip()
            if prev.endswith(","):
                sys.stderr.write("\nIndice: virgule en trop a la fin de la ligne %d.\n"
                                 % (e.lineno - 1))
        sys.stderr.write("\n")
        raise SystemExit(2)


def _url_key(url):
    u = (url or "").lower().split("?")[0]
    u = re.sub(r"^https?://", "", u)
    return u.rstrip("/")


def build_catalog(cfg, args, quiet=False):
    """Deplie sources.json: groupes -> listes, avec heritage du `base` et des
    `defaults`. Aucune decouverte automatique: ce que declare le fichier est
    exactement ce qui sera telecharge."""
    defaults = cfg.get("defaults", {})
    catalog, seen_ids, seen_urls = [], set(), set()

    for grp in cfg.get("groups", []):
        if not grp.get("enabled", True):
            continue
        base = grp.get("base", "")
        for item in grp.get("lists", []):
            if not item.get("enabled", defaults.get("enabled", True)):
                continue
            url = item.get("url") or (base + item["file"] if item.get("file") else "")
            if not url:
                log("  ! %s: ni url ni file, ignoree" % item.get("id"), quiet)
                continue
            sid = item["id"]
            if sid in seen_ids:
                log("  ! identifiant en double, ignore: %s" % sid, quiet)
                continue
            ukey = _url_key(url)
            if ukey in seen_urls:
                log("  ! URL en double, ignoree: %s" % sid, quiet)
                continue
            seen_ids.add(sid)
            seen_urls.add(ukey)
            catalog.append({
                "id": sid,
                "name": item["name"],
                "description": item.get("note", ""),
                "url": url,
                "mirror_url": "",
                "source_kind": "officiel",
                "homepage": item.get("homepage", grp.get("homepage", "")),
                "group": grp.get("maintainer", grp["id"]),
                "group_id": grp["id"],
                "tags": item.get("tags", []),
                "languages": item.get("languages", []),
                "expires": int(item.get("expires", defaults.get("expires", 86400))),
                "format": item.get("format", defaults.get("format", "adblock")),
                "registry_version": "",
            })

    # Filtres de ligne de commande
    kept = []
    for src in catalog:
        if args.group:
            wanted = [w.lower() for w in args.group]
            if src["group_id"].lower() not in wanted and src["group"].lower() not in wanted:
                continue
        if args.only:
            hay = ("%s %s" % (src["id"], src["name"])).lower()
            if not any(n.lower() in hay for n in args.only):
                continue
        kept.append(src)

    # Slug de fichier, avec resolution des collisions.
    seen = {}
    for src in kept:
        slug = slugify(src["name"])
        if slug in seen:
            slug = "%s-%s" % (slug, src["id"])
        seen[slug] = True
        src["slug"] = slug
        src["file"] = slug + ".txt"
    return kept

# --------------------------------------------------------------------------- #
# Telechargement
# --------------------------------------------------------------------------- #

def fetch_one(src, out_dir, state, args):
    """Retourne un dict d'etat pour cette liste."""
    path = os.path.join(out_dir, src["file"])
    prev = state.get(src["id"], {})
    entry = dict(src)
    entry.pop("origin", None)

    exists = os.path.isfile(path)

    # Court-circuit: liste encore "fraiche" selon son champ Expires.
    if exists and not args.force and prev.get("fetched_at"):
        try:
            age = time.time() - datetime.fromisoformat(prev["fetched_at"]).timestamp()
            if age < min(src["expires"], args.max_age):
                entry.update(prev)
                entry["status"] = "fresh"
                return entry
        except Exception:  # noqa: BLE001
            pass

    etag = None if args.force else prev.get("etag")
    lastmod = None if args.force else prev.get("last_modified")
    if not exists or prev.get("includes"):
        etag = lastmod = None

    try:
        status, body, headers = http_get(
            src["url"], timeout=args.timeout, etag=etag,
            last_modified=lastmod, retries=args.retries)
    except Exception as e:  # noqa: BLE001
        fallback = src.get("mirror_url")
        if fallback:
            try:
                status, body, headers = http_get(
                    fallback, timeout=args.timeout, retries=args.retries)
                entry["source_kind"] = "miroir (repli)"
                entry["fallback_reason"] = str(e)
            except Exception as e2:  # noqa: BLE001
                entry.update(prev)
                entry["status"] = "failed"
                entry["error"] = "%s ; repli: %s" % (e, e2)
                return entry
        else:
            entry.update(prev)
            entry["status"] = "failed"
            entry["error"] = str(e)
            return entry

    if status == 304:
        entry.update(prev)
        entry["status"] = "unchanged"
        entry["fetched_at"] = now_iso()
        entry.pop("error", None)
        return entry

    text = body.decode("utf-8", errors="replace")
    included = preproc_dropped = 0
    if "!#include" in text:
        text, included = resolve_includes(text, src["url"], args.timeout)
    text, preproc_dropped = apply_preprocessor(text)
    if included or preproc_dropped:
        body = text.encode("utf-8")
    if len(text.strip()) < 32:
        entry.update(prev)
        entry["status"] = "failed"
        entry["error"] = "reponse vide ou tronquee (%d octets)" % len(body)
        return entry

    digest = hashlib.sha256(body).hexdigest()
    changed = digest != prev.get("sha256") or not exists
    if changed and not args.dry_run:
        atomic_write_bytes(path, body)

    meta = parse_header(text)
    n_rules, rules_hash = count_rules(text)
    entry.update({
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified"),
        "sha256": digest,
        "bytes": len(body),
        "lines": text.count("\n") + 1,
        "rules": n_rules,
        "rules_sha256": rules_hash,
        "title": meta.get("title", src["name"]),
        "version": meta.get("version", src.get("registry_version", "")),
        "list_updated": meta.get("timeupdated") or meta.get("last_modified", ""),
        "license": meta.get("license", ""),
        "fetched_at": now_iso(),
        "includes": included,
        "preproc_dropped": preproc_dropped,
        "status": "updated" if changed else "unchanged",
    })
    entry.pop("error", None)
    return entry


def main():
    ap = argparse.ArgumentParser(
        description="Telecharge et met a jour la base des listes de filtres adblock.")
    ap.add_argument("--sources", default=DEFAULT_SOURCES, help="chemin de sources.json")
    ap.add_argument("--out", default=DEFAULT_OUT, help="dossier de sortie (defaut: filters/)")
    ap.add_argument("--only", nargs="+", metavar="MOTIF",
                    help="ne garder que les listes dont l'id/nom contient un de ces motifs")
    ap.add_argument("--group", nargs="+", metavar="GROUPE",
                    help="filtre par groupe: ublock, adguard, adguard-dns, adguard-lang, "
                         "easylist, easylist-lang, fanboy, dandelion, hagezi, dns, "
                         "security, regional, other")
    ap.add_argument("--force", action="store_true", help="ignorer cache HTTP et fraicheur")
    ap.add_argument("--max-age", type=int, default=86400,
                    help="age max en secondes avant re-verification (defaut: 86400)")
    ap.add_argument("--jobs", type=int, default=8, help="telechargements paralleles (defaut: 8)")
    ap.add_argument("--timeout", type=int, default=60, help="timeout HTTP en secondes")
    ap.add_argument("--retries", type=int, default=3, help="tentatives par source")
    ap.add_argument("--list", action="store_true", dest="list_only",
                    help="afficher le catalogue et sortir")
    ap.add_argument("--dry-run", action="store_true", help="ne rien ecrire sur le disque")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.sources)
    log("Construction du catalogue...", args.quiet)
    catalog = build_catalog(cfg, args, args.quiet)
    if not catalog:
        log("Aucune source retenue.", args.quiet)
        return 1

    if args.list_only:
        for src in catalog:
            print("%-14s %-22s %s" % (src["id"], src["group"][:22], src["name"]))
        print("\n%d listes." % len(catalog))
        return 0

    os.makedirs(args.out, exist_ok=True)
    index_path = os.path.join(args.out, INDEX_NAME)
    state = {}
    if os.path.isfile(index_path):
        try:
            with open(index_path, "r", encoding="utf-8") as fh:
                state = json.load(fh).get("lists", {})
        except Exception:  # noqa: BLE001
            state = {}

    log("%d listes a traiter (%d threads)\n" % (len(catalog), args.jobs), args.quiet)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(fetch_one, s, args.out, state, args): s for s in catalog}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            src = futs[fut]
            done += 1
            try:
                entry = fut.result()
            except Exception as e:  # noqa: BLE001
                entry = dict(src)
                entry["status"] = "failed"
                entry["error"] = str(e)
            results[src["id"]] = entry
            mark = {"updated": "+", "unchanged": "=", "fresh": ".", "failed": "x"}
            log("  [%3d/%3d] %s %-46s %s" % (
                done, len(catalog), mark.get(entry["status"], "?"),
                src["name"][:46],
                entry.get("error", "%s regles" % entry.get("rules", "?"))), args.quiet)

    ordered = {s["id"]: results[s["id"]] for s in catalog}

    # Un slug qui change (renommage amont, desambiguisation) laisse un .txt
    # orphelin que le convertisseur reprendrait comme une liste fantome.
    if not (args.only or args.group or args.dry_run):
        declared = {e["file"] for e in ordered.values() if e.get("file")}
        for name in os.listdir(args.out):
            if name.endswith(".txt") and name not in declared:
                os.remove(os.path.join(args.out, name))
                log("  - fichier orphelin supprime: %s" % name, args.quiet)

    # Deux sources d'URL differentes peuvent livrer un contenu identique
    # (ex. uBO annoyances.txt n'inclut que annoyances-others.txt). On garde la
    # premiere et on marque les autres, pour ne pas convertir deux fois.
    by_hash = {}
    for sid, e in ordered.items():
        h = e.get("rules_sha256")
        if not h or e.get("status") == "failed":
            continue
        if h in by_hash:
            e["duplicate_of"] = by_hash[h]
        else:
            by_hash[h] = sid
            e.pop("duplicate_of", None)
    counts = {}
    for e in ordered.values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1

    if not args.dry_run:
        index = {
            "generated_at": now_iso(),
            "generator": "fetch_filters.py",
            "count": len(ordered),
            "summary": counts,
            "lists": ordered,
        }
        tmp = index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, ensure_ascii=False, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, index_path)

    total_rules = sum(e.get("rules") or 0 for e in ordered.values())
    log("\n%s" % ("-" * 60), args.quiet)
    log("mises a jour: %d | inchangees: %d | fraiches: %d | echecs: %d"
        % (counts.get("updated", 0), counts.get("unchanged", 0),
           counts.get("fresh", 0), counts.get("failed", 0)), args.quiet)
    log("total: %d regles brutes dans %s" % (total_rules, args.out), args.quiet)
    return 0 if counts.get("failed", 0) < len(ordered) else 2


if __name__ == "__main__":
    sys.exit(main())
