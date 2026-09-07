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
    """Compte les lignes utiles (ni vides, ni commentaires)."""
    n = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "!#" or s.startswith("["):
            continue
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #

def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def discover_adguard(registry_url, timeout, quiet=False, id_prefix="adguard"):
    """Lit un registre AdGuard (extension ou hostlists DNS) et le normalise.

    Les deux registres partagent le meme schema: groups / tags / filters.
    """
    log("  registre %s: %s" % (id_prefix, registry_url), quiet)
    status, body, _ = http_get(registry_url, timeout=timeout)
    if status != 200 or not body:
        raise RuntimeError("registre inaccessible (status %s)" % status)
    data = json.loads(body.decode("utf-8"))

    groups = {g["groupId"]: g["groupName"] for g in data.get("groups", [])}
    tags = {t["tagId"]: t["keyword"] for t in data.get("tags", [])}

    out = []
    for f in data.get("filters", []):
        keywords = [tags.get(t, "") for t in f.get("tags", [])]
        keywords = [k for k in keywords if k]
        out.append({
            "id": "%s-%s" % (id_prefix, f["filterId"]),
            "registry_id": f["filterId"],
            "name": f["name"],
            "description": f.get("description", ""),
            "url": f.get("downloadUrl") or f.get("subscriptionUrl"),
            "homepage": f.get("homepage", ""),
            "group": groups.get(f.get("groupId"), "Other"),
            "tags": keywords,
            "languages": f.get("languages", []),
            "deprecated": bool(f.get("deprecated")),
            "expires": int(f.get("expires") or 86400),
            "registry_version": f.get("version", ""),
            "format": "adblock",
            "origin": "adguard-registry",
        })
    return out


# Syntaxes FilterLists convertibles par ce pipeline.
FILTERLISTS_SYNTAXES = {
    1: "hosts",     # Hosts (localhost IPv4)
    2: "hosts",     # Domains
    3: "adblock",   # Adblock Plus
    4: "adblock",   # uBlock Origin Static
    6: "adblock",   # AdGuard
    14: "hosts",    # Non-localhost hosts (IPv4)
}


def discover_filterlists(reg, timeout, jobs, quiet=False):
    """Annuaire FilterLists.com. Necessite un appel de detail par liste."""
    index_url = reg.get("url", "https://api.filterlists.com/lists")
    log("  registre filterlists: %s" % index_url, quiet)
    status, body, _ = http_get(index_url, timeout=timeout)
    if status != 200 or not body:
        raise RuntimeError("annuaire inaccessible (status %s)" % status)
    listing = json.loads(body.decode("utf-8"))

    allowed = set(reg.get("syntaxes") or FILTERLISTS_SYNTAXES.keys())
    wanted = [x for x in listing
              if set(x.get("syntaxIds") or []) & allowed]
    limit = reg.get("max_lists")
    if limit:
        wanted = wanted[:int(limit)]
    log("  %d listes retenues sur %d, recuperation des URL..."
        % (len(wanted), len(listing)), quiet)

    detail_url = index_url.rstrip("/") + "/%d"

    def detail(item):
        try:
            st, bd, _ = http_get(detail_url % item["id"], timeout=timeout, retries=2)
            if st != 200 or not bd:
                return None
            return json.loads(bd.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(jobs, 12)) as pool:
        for d in pool.map(detail, wanted):
            if not d:
                continue
            urls = sorted(d.get("viewUrls") or [],
                          key=lambda v: (v.get("primariness", 9),
                                         v.get("segmentNumber", 9)))
            if not urls:
                continue
            syntax = next((FILTERLISTS_SYNTAXES[s] for s in (d.get("syntaxIds") or [])
                           if s in FILTERLISTS_SYNTAXES), "adblock")
            out.append({
                "id": "fl-%s" % d["id"],
                "registry_id": None,
                "name": d["name"],
                "description": (d.get("description") or "")[:300],
                "url": urls[0]["url"],
                "homepage": d.get("homeUrl") or "",
                "group": "FilterLists",
                "tags": [],
                "languages": [],
                "deprecated": False,
                "expires": 86400,
                "registry_version": "",
                "format": syntax,
                "origin": "filterlists",
            })
    return out


def _url_key(url):
    u = (url or "").lower().split("?")[0]
    u = re.sub(r"^https?://", "", u)
    return u.rstrip("/")


def build_catalog(cfg, args, quiet=False):
    catalog = []

    if not args.no_discover:
        for reg in cfg.get("registries", []):
            if not reg.get("enabled", True):
                continue
            kind = reg.get("type")
            try:
                if kind in ("adguard-registry", "adguard-hostlists"):
                    catalog.extend(discover_adguard(
                        reg["url"], args.timeout, quiet,
                        id_prefix=reg.get("id", "adguard")))
                elif kind == "filterlists":
                    catalog.extend(discover_filterlists(
                        reg, args.timeout, args.jobs, quiet))
                else:
                    log("  ! type de registre inconnu, ignore: %s" % kind, quiet)
            except Exception as e:  # noqa: BLE001
                log("  ! decouverte %s echouee: %s" % (reg.get("id"), e), quiet)

    for extra in cfg.get("extra", []):
        if not extra.get("enabled", True):
            continue
        catalog.append({
            "id": extra["id"],
            "registry_id": None,
            "name": extra["name"],
            "description": extra.get("comment", ""),
            "url": extra["url"],
            "homepage": extra.get("homepage", ""),
            "group": extra.get("group", "Other"),
            "tags": extra.get("tags", []),
            "languages": [],
            "deprecated": False,
            "expires": int(extra.get("expires") or 86400),
            "registry_version": "",
            "format": extra.get("format", "adblock"),
            "origin": "extra",
        })

    sel = cfg.get("selection", {})
    excl_tags = set(sel.get("exclude_tags", []))
    excl_groups = set(sel.get("exclude_groups", []))
    excl_ids = set(str(x) for x in sel.get("exclude_ids", []))
    incl_ids = set(str(x) for x in sel.get("include_ids", []))
    only_reco = args.recommended or sel.get("only_recommended", False)
    keep_deprecated = args.deprecated or sel.get("include_deprecated", False)

    kept = []
    seen_urls = set()
    for src in catalog:
        if not src.get("url"):
            continue
        ukey = _url_key(src["url"])
        if ukey in seen_urls:
            continue
        seen_urls.add(ukey)
        if src["deprecated"] and not keep_deprecated:
            continue
        if excl_tags & set(src["tags"]):
            continue
        if src["group"] in excl_groups:
            continue
        if src["id"] in excl_ids or str(src.get("registry_id")) in excl_ids:
            continue
        if incl_ids and not (src["id"] in incl_ids or str(src.get("registry_id")) in incl_ids):
            continue
        if only_reco and "recommended" not in src["tags"] and src["origin"] != "extra":
            continue
        if args.group and src["group"].lower() not in [g.lower() for g in args.group]:
            continue
        if args.tag and not (set(args.tag) & set(src["tags"])):
            continue
        if args.only:
            needles = [n.lower() for n in args.only]
            hay = ("%s %s" % (src["id"], src["name"])).lower()
            if not any(n in hay for n in needles):
                continue
        kept.append(src)

    # Slug + resolution des collisions de noms de fichier.
    seen = {}
    for src in kept:
        slug = slugify(src["name"])
        if slug in seen:
            slug = "%s-%s" % (slug, src["id"])
        seen[slug] = True
        src["slug"] = slug
        src["file"] = slug + ".txt"

    kept.sort(key=lambda s: (s["group"], s["name"].lower()))
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
    if not exists:
        etag = lastmod = None

    try:
        status, body, headers = http_get(
            src["url"], timeout=args.timeout, etag=etag,
            last_modified=lastmod, retries=args.retries)
    except Exception as e:  # noqa: BLE001
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
    entry.update({
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified"),
        "sha256": digest,
        "bytes": len(body),
        "lines": text.count("\n") + 1,
        "rules": count_rules(text),
        "title": meta.get("title", src["name"]),
        "version": meta.get("version", src.get("registry_version", "")),
        "list_updated": meta.get("timeupdated") or meta.get("last_modified", ""),
        "license": meta.get("license", ""),
        "fetched_at": now_iso(),
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
                    help='filtre par groupe ("Ad blocking", Privacy, Annoyances, Security, ...)')
    ap.add_argument("--tag", nargs="+", metavar="TAG",
                    help="filtre par tag AdGuard (recommended, purpose:ads, lang:fr, ...)")
    ap.add_argument("--recommended", action="store_true",
                    help="uniquement les listes taguees 'recommended'")
    ap.add_argument("--deprecated", action="store_true", help="inclure les listes depreciees")
    ap.add_argument("--no-discover", action="store_true",
                    help="ne pas interroger le registre AdGuard (sources.json 'extra' seulement)")
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
