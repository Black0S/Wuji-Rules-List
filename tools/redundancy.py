#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/redundancy.py — annote sources.json avec le recouvrement entre listes.

Deux listes du catalogue peuvent bloquer largement la meme chose: EasyList est
entierement contenue dans AdGuard Base, Peter Lowe dans Steven Black. Rien ne
le signalait, alors qu'un content blocker Safari ne compile que 150 000 regles:
en activer deux qui se recouvrent gaspille le budget sans rien ajouter.

Ce script mesure, pour chaque liste A et chaque autre liste B, la part des
regles de blocage de A deja presentes dans B, et ecrit le resultat dans le
champ `covered_by` de l'entree A.

    python3 tools/redundancy.py            # annote sources.json
    python3 tools/redundancy.py --dry-run  # affiche sans ecrire

A lancer apres convert_webkit.py, dont il lit la sortie.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "webkit-rules")
SOURCES = os.path.join(ROOT, "sources.json")


def load_sets(catalog):
    """Empreintes des regles de blocage de chaque liste publiee."""
    sets = {}
    for entry in catalog["lists"]:
        acc = set()
        for f in entry["files"]:
            path = os.path.join(OUT, f["file"])
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                for rule in json.load(fh):
                    if rule.get("action", {}).get("type") == "block":
                        acc.add(hash(rule["trigger"]["url-filter"]))
        if acc:
            sets[entry["id"]] = (entry["name"], acc)
    return sets


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--threshold", type=int, default=50,
                    help="pourcentage minimal pour signaler un recouvrement")
    ap.add_argument("--max", type=int, default=3,
                    help="nombre maximal de recouvrements listes par entree")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    index = os.path.join(OUT, "index.json")
    if not os.path.isfile(index):
        print("Lancer convert_webkit.py d'abord (%s absent)." % index, file=sys.stderr)
        return 1
    with open(index, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)

    sets = load_sets(catalog)
    print("%d listes comparees" % len(sets), file=sys.stderr)

    covered = {}
    for a, (na, sa) in sets.items():
        rows = []
        for b, (nb, sb) in sets.items():
            if a == b:
                continue
            pct = int(round(100.0 * len(sa & sb) / len(sa)))
            if pct >= args.threshold:
                rows.append({"id": b, "name": nb, "pct": pct})
        rows.sort(key=lambda r: -r["pct"])
        if rows:
            covered[a] = rows[:args.max]

    with open(SOURCES, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    changed = 0
    for grp in cfg.get("groups", []):
        for item in grp.get("lists", []):
            rows = covered.get(item["id"])
            if rows:
                if item.get("covered_by") != rows:
                    changed += 1
                item["covered_by"] = rows
            elif "covered_by" in item:
                del item["covered_by"]
                changed += 1

    note = ("`covered_by` est calcule par tools/redundancy.py: part des regles de "
            "blocage de cette liste deja presentes dans une autre du catalogue. "
            "100 signifie que la liste n'apporte rien de plus. Un content blocker "
            "Safari ne compile que 150 000 regles: activer deux listes qui se "
            "recouvrent gaspille ce budget. Champ informatif, sans effet sur la "
            "conversion.")
    cfg["$comment_covered_by"] = note

    if args.dry_run:
        for a, rows in sorted(covered.items(), key=lambda kv: -kv[1][0]["pct"]):
            print("%-34s %s" % (sets[a][0][:34],
                                ", ".join("%s %d%%" % (r["name"][:26], r["pct"]) for r in rows)))
        return 0

    with open(SOURCES, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("%d entrees annotees (%d modifiees)" % (len(covered), changed), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
